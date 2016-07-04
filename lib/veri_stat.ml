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

module R = Regular.Make(struct
    type nonrec t = t [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_stat"
    let version = "0.1"

    let pp_count fmt (name, cnt) = 
      if cnt <> 0 then
        Format.fprintf fmt "%s: %d; " name cnt

    let pp_lift_errors fmt t = 
      mislifted_names t |>
      List.iter ~f:(fun insn ->
          Format.fprintf fmt "%s mis-lifted\n" insn) 

    let pp fmt t = 
      Map.iteri ~f:(fun ~key ~data ->
          let ok, er = data in
          if er <> 0 then
            Format.fprintf fmt "%s mis-executed %d times(%d successfully)\n"
              key er ok) t.calls;
      Format.fprintf fmt "%a" pp_lift_errors t;
      Format.fprintf fmt "%a%a%a%a%a%a\n"
        pp_count ("overloaded chunks", overloaded_count t)
        pp_count ("undisasmed", undisasmed_count t)
        pp_count ("misexecuted", misexecuted_count t)
        pp_count ("mislifted ", mislifted_count t)
        pp_count ("damaged", damaged_count t)
        pp_count ("successed", successed_count t)

  end)

module Summary = struct

  type s = {
    overloaded : float;
    undisasmed : float;
    misexecuted: float;
    mislifted  : float;
    damaged    : float;
    successed  : float;
  } [@@deriving bin_io, compare, sexp]
  
  type t = s option [@@deriving bin_io, compare, sexp]
      
  let to_percent n d = float n /. float d *. 100.0
  let overloaded stat = to_percent (overloaded_count stat) (entries_count stat)
  let undisasmed stat = to_percent (undisasmed_count stat) (entries_count stat)
  let misexecuted stat =to_percent (misexecuted_count stat) (entries_count stat)
  let mislifted stat = to_percent (mislifted_count stat) (entries_count stat)
  let damaged stat = to_percent (damaged_count stat) (entries_count stat)
  let successed stat = to_percent (successed_count stat) (entries_count stat)

  let create stat =
    if entries_count stat = 0 then None
    else
      Some ({
          overloaded = overloaded stat;
          undisasmed = undisasmed stat;
          misexecuted = misexecuted stat;
          mislifted   = mislifted stat;
          damaged     = damaged stat;
          successed   = successed stat;
        })

  include Regular.Make(struct
      type nonrec t = t [@@deriving bin_io, compare, sexp]
      let compare = compare
      let hash = Hashtbl.hash
      let module_name = Some "Veri_stat.Summary"
      let version = "0.1"

      let pp fmt t =
        match t with
        | None -> Format.fprintf fmt "summary is unavailable\n"
        | Some t ->
          Format.fprintf fmt "overloaded: %.2f%%; undisasmed %.2f%%; \
                              misexecuted %.2f%%; mislifted %.2f%%; \
                              damaged %.2f%%; successed %.2f%%\n" 
            t.overloaded t.undisasmed 
            t.misexecuted t.mislifted 
            t.damaged t.successed 
    end)
end

let make_summary stat = Summary.create stat

include R
