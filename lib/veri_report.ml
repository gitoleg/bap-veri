open Core_kernel.Std
open Bap.Std
open Bap_traces.Std 
open Regular.Std

module Names = String.Map

type events = Value.Set.t [@@deriving bin_io, compare, sexp]
type frame_diff = events * events [@@deriving bin_io, compare, sexp]

type t = {
  frames : frame_diff list Names.t;
  errors : Veri_error.t list;
} [@@deriving bin_io, sexp]

let create () = { frames = Names.empty; errors = []; }

let update t name diff =
  let frames = 
    Map.change t.frames name
      (function 
        | None -> Some [diff]
        | Some diffs -> Some (diff :: diffs)) in
  {t with frames}

let frames {frames} = Map.to_alist frames
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

    let pp_ev fmt ev = Format.fprintf fmt "%a; " Value.pp ev
    let pp_events fmt evs = Set.iter evs ~f:(pp_ev fmt)
        
    let pp_diff fmt (left, right) = 
      Format.fprintf fmt "left: %a\nright: %a\n"  
        pp_events left pp_events right

    let pp_frames fmt (name, diffs) = 
      let open Format in
      fprintf fmt "%s\n" name;
      List.iter ~f:(fun d -> pp_diff fmt d;) diffs
      
    let pp fmt t =
      List.iter ~f:(pp_frames fmt) (frames t);
      Format.fprintf fmt "errors statistic: \
        overloaded chunks: %d; damaged chunks: %d; \
        disasm errors: %d; lifter errors: %d\n"  
        (overloaded_count t) (damaged_count t) (disasm_count t)
        (lifter_count t) 

    let module_name = Some "Veri_Report"
    let version = "0.1"
  end)
