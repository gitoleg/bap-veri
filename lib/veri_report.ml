open Core_kernel.Std
open Bap.Std
open Bap_traces.Std 
open Regular.Std
open Veri_policy

module Names = String.Map

type call = (rule * matched) list  [@@deriving bin_io, sexp]
type bind = string * call list  [@@deriving bin_io, sexp]

type t = {
  calls  : (call list) Names.t;
  errors : Veri_error.t list;
} [@@deriving bin_io, sexp]

let create () = { calls = Names.empty; errors = []; }

let update t name cl =
  {t with 
   calls =
     Map.change t.calls name
       (function 
         | None -> Some [cl]
         | Some cls -> Some (cl :: cls)) }

let binds {calls} : bind list = Map.to_alist calls
let errors t = t.errors
let notify t er = {t with errors = er :: t.errors }
let errors_count t ~f = List.count t.errors ~f

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

    let pp_ev fmt ev = 
      Format.fprintf fmt "%a; " Value.pp ev

    let pp_events fmt pref evs = 
      Format.fprintf fmt "%s: " pref;
      List.iter ~f:(pp_ev fmt) evs;
      Format.print_newline ()

    let pp_matched fmt matched = match matched with
      | Left evs -> pp_events fmt "left" evs
      | Right evs -> pp_events fmt "right" evs
      | Both pairs -> 
        Format.fprintf fmt "both: ";
        List.iter pairs
          ~f:(fun (e, e') -> Format.fprintf fmt "%a, %a; " Value.pp e Value.pp e')
          
    let pp_call fmt call = 
      List.iter call ~f:(fun (rule, matched) ->
          Format.fprintf fmt "%a\n%a\n" Rule.pp rule pp_matched matched)

    let pp_calls fmt (calls : call list) = List.iter calls ~f:(pp_call fmt)
     
    let pp_binds fmt (binds : bind list) = 
      List.iter binds ~f:(fun (insn, calls) ->
          Format.fprintf fmt "%s:\n%a" insn pp_calls calls);
      Format.print_newline ()

    let pp fmt t = 
      pp_binds fmt (binds t);
      Format.fprintf fmt "errors statistic: \
                          overloaded chunks: %d; damaged chunks: %d; \
                          disasm errors: %d; lifter errors: %d\n"
        (overloaded_count t) (damaged_count t) (disasm_count t)
        (lifter_count t)

    let module_name = Some "Veri_Report"
    let version = "0.1"
  end)
