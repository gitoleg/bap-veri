open Core_kernel.Std
open Regular.Std

module Names = String.Map

type ok_er = int * int [@@deriving bin_io, compare, sexp]

type t = {
  calls : ok_er Names.t;
  errors: Veri_error.t list;
} [@@deriving bin_io, compare, sexp]

let create () = { calls = Names.empty; errors = []; }
let errors t = t.errors
let notify t er = {t with errors = er :: t.errors }
let errors_count t ~f = List.count t.errors ~f

let entries_count t = 
  List.length t.errors + 
  Map.fold ~f:(fun ~key ~data cnt -> cnt + fst data + snd data) ~init:0 t.calls

let update t name ~ok ~er = 
  {t with 
   calls =
     Map.change t.calls name
       (function 
         | None -> Some (ok, er)
         | Some (ok',er') -> Some (ok + ok', er + er')) } 

let failbil t name = update t name ~ok:0 ~er:1
let success t name = update t name ~ok:1 ~er:0

let successed_count {calls} =
  Map.fold ~f:(fun ~key ~data cnt -> cnt + fst data) ~init:0 calls

let misexecuted_count {calls} =
  Map.fold ~f:(fun ~key ~data cnt -> cnt + snd data) ~init:0 calls

let overloaded_count t = errors_count t 
    ~f:(function 
        | `Overloaded_chunk -> true 
        | _ -> false)

let damaged_count t = errors_count t 
    ~f:(function 
        | `Damaged_chunk _ -> true 
        | _ -> false)

let undisasmed_count t = errors_count t 
    ~f:(function 
        | `Disasm_error _ -> true 
        | _ -> false)

let mislifted_count t = errors_count t 
    ~f:(function 
        | `Lifter_error _ -> true 
        | _ -> false)

let mislifted_names t = 
  List.fold_left ~init:String.Set.empty 
    ~f:(fun names errs ->
        match errs with 
        | `Lifter_error (insn,_) -> Set.add names insn
        | _ -> names) t.errors |>
  Set.to_list

let print_table fmt info data = 
  let open Textutils.Std in
  let open Ascii_table in
  let make_col name f = Column.create name f in
  let cols = 
    List.fold ~f:(fun acc (name, f) -> make_col name f :: acc) ~init:[] info |> 
    List.rev in
  let stringify display =
    Printf.sprintf "%s\n%!"
      (to_string ~bars:`Ascii ~display cols data) in
  Format.fprintf fmt "%s" (stringify Display.short_box)

module R = Regular.Make(struct
    type nonrec t = t [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_stat"
    let version = "0.1"

    let pp_misexecuted fmt = function
      | [] -> ()
      | mis -> 
        print_table fmt 
          [ "instruction", fst;
            "failed", (fun (_, (_,er)) -> Printf.sprintf "%d" er);
            "successful", (fun (_, (ok,_)) -> Printf.sprintf "%d" ok); ] 
          mis

    let pp_name fmt name = Format.fprintf fmt "%s @," name
    let pp_names fmt names = List.iter ~f:(pp_name fmt) names

    let pp_mislifted fmt = function 
      | [] -> ()
      | names ->
        let names' = "mis-lifted:" :: names in
        Format.fprintf fmt "@[<b>%a@]" pp_names names'
        
    let pp fmt t = 
      let misexec = 
        List.filter ~f:(fun (_,(_,er)) -> er <> 0) (Map.to_alist t.calls) in
      let mislift = mislifted_names t in
      Format.fprintf fmt "%a\n%a\n"
        pp_misexecuted misexec pp_mislifted mislift
  end)

module Summary = struct

  (** what, relative count, absolute count *)
  type p = string * float * int [@@deriving bin_io, sexp, compare]
  type t = p list [@@deriving bin_io, sexp, compare]

  let to_percent n d  = float n /. float d *. 100.0      

  let make_p stat name f = 
    let nom, denom = f stat, entries_count stat in
    name, to_percent nom denom, nom

  let create stat =
    if entries_count stat = 0 then []
    else
      [ make_p stat "overloaded" overloaded_count;
        make_p stat "undisasmed" undisasmed_count;
        make_p stat "misexecuted" misexecuted_count;
        make_p stat "mislifted" mislifted_count; 
        make_p stat "damaged"  damaged_count;
        make_p stat "successed" successed_count; ]

  include Regular.Make(struct
      type nonrec t = t [@@deriving bin_io, compare, sexp]
      let compare = compare
      let hash = Hashtbl.hash
      let module_name = Some "Veri_stat.Summary"
      let version = "0.1"

      let pp fmt = function
        | [] -> Format.fprintf fmt "summary is unavailable\n"
        | ps ->
          print_table fmt 
            ["", (fun (x,_,_) -> x);
             "rel", (fun (_,x,_) -> Printf.sprintf "%.2f%%" x);
             "abs",  (fun (_,_,x) -> Printf.sprintf "%d" x);]
            ps
    end)

end

let make_summary stat = Summary.create stat

include R
