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

let lifter_count t =  errors_count t 
    ~f:(function 
        | `Lifter_error _ -> true 
        | _ -> false)

type s = t [@@deriving bin_io, compare, sexp]

include Regular.Make(struct
    type t = s [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_stat"
    let version = "0.1"

    let pp fmt t = 
      Map.iteri ~f:(fun ~key ~data -> 
          let ok, er = data in
          if er <> 0 then
            Format.fprintf fmt "%s mis-executed %d times(%d successfully)\n"
              key er ok) t.calls;
      Format.fprintf fmt "errors statistic: \
                          bil errors : %d; \
                          overloaded chunks: %d; damaged chunks: %d; \
                          disasm errors: %d; lifter errors: %d\n"
        (bil_errors t) (overloaded_count t) (damaged_count t) (disasm_count t)
        (lifter_count t)
  end)


