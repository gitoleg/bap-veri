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

let update t name ~ok ~er = 
  {t with 
   calls =
     Map.change t.calls name
       (function 
         | None -> Some (ok, er)
         | Some (ok',er') -> Some (ok + ok', er + er')) } 

let failbil t name = update t name ~ok:0 ~er:1
let success t name = update t name ~ok:1 ~er:0

let bil_errors {calls} =
  Map.fold ~f:(fun ~key ~data cnt -> cnt + snd data) ~init:0 calls

let overloaded_count t = errors_count t 
    ~f:(function 
        | `Overloaded_chunk -> true 
        | _ -> false)

let damaged_count t = errors_count t 
    ~f:(function 
        | `Damaged_chunk _ -> true 
        | _ -> false)

let disasm_count t =  errors_count t 
    ~f:(function 
        | `Disasm_error _ -> true 
        | _ -> false)

let mislifted t = 
  List.fold_left ~init:String.Set.empty 
    ~f:(fun names errs ->
        match errs with 
        | `Lifter_error (insn,_) -> Set.add names insn
        | _ -> names) t.errors |>
  Set.to_list

include Regular.Make(struct
    type nonrec t = t [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_stat"
    let version = "0.1"

    let pp_count fmt (name,cnt) = 
      if cnt <> 0 then
        Format.fprintf fmt "%s: %d; " name cnt

    let pp_lift_errors fmt names = 
      List.iter ~f:(fun insn ->
          Format.fprintf fmt "%s mis-lifted\n" insn) names

    let pp fmt t = 
      Map.iteri ~f:(fun ~key ~data -> 
          let ok, er = data in
          if er <> 0 then
            Format.fprintf fmt "%s mis-executed %d times(%d successfully)\n"
              key er ok) t.calls;
      Format.fprintf fmt "%a" pp_lift_errors (mislifted t);
      Format.fprintf fmt "%a%a%a%a\n"
        pp_count ("bil errors", bil_errors t)
        pp_count ("overloaded chunks", overloaded_count t)
        pp_count ("damaged chunks", damaged_count t)
        pp_count ("disasm errors", disasm_count t);
  end)


