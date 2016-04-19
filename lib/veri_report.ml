open Core_kernel.Std
open Bap.Std
open Bap_traces.Std 
open Regular.Std
open Veri_policy

module Names = String.Map
module Rules = Rule.Map

type frame = matched list Rules.t [@@deriving bin_io, sexp]

type t = {
  frames : frame Names.t;
  errors : Veri_error.t list;
} [@@deriving bin_io, sexp]

let create () = { frames = Names.empty; errors = []; }

let make_frame rule matched = Map.add Rules.empty rule [matched]

let update_frame: frame -> rule -> matched -> frame = fun frame rule matched ->
  Map.change frame rule
    (function 
      | None -> Some [matched]
      | Some ms -> Some (matched :: ms)) 

let update t name rule matched =
  let frames = 
    Map.change t.frames name
      (function 
        | None -> Some (make_frame rule matched)
        | Some frame -> 
          Some (update_frame frame rule matched)) in
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

    let pp_frame fmt frame = 
      let items = Map.to_alist frame in 
      List.iter items ~f:(fun (rule, matches) ->
          Format.fprintf fmt "%a\n" Rule.pp rule;
          List.iter matches ~f:(pp_matched fmt);
          Format.print_newline ())
     
    let pp_frames fmt frames = 
      let items = Map.to_alist frames in
      List.iter items ~f:(fun (insn, frame) ->
          Format.fprintf fmt "%s:\n%a" insn pp_frame frame);
      Format.print_newline ()

    let pp fmt t = 
      pp_frames fmt t.frames;
      Format.fprintf fmt "errors statistic: \
                          overloaded chunks: %d; damaged chunks: %d; \
                          disasm errors: %d; lifter errors: %d\n"
        (overloaded_count t) (damaged_count t) (disasm_count t)
        (lifter_count t)

    let module_name = Some "Veri_Report"
    let version = "0.1"
  end)
