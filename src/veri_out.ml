open Core_kernel.Std
open Textutils.Std
open Text_block

module Q = Veri_numbers.Q

let make_iota max =
  let rec make acc n =
    if n < 0 then acc
    else make (n :: acc) (n - 1) in
  make [] (max - 1)

let make_col title to_string vals =
  vcat ~align:`Center (text title :: List.map ~f:(fun x -> text (to_string x)) vals)

let texts_col title vals = make_col title ident vals
let intgr_col title vals = make_col title (Printf.sprintf "%d") vals
let float_col title vals = make_col title (Printf.sprintf "%.2f") vals

let output stats path =
  let of_stats f = List.map ~f:(fun x -> f (snd x)) stats in
  let out = Out_channel.create path in
  let cnter = intgr_col "#" (make_iota (List.length stats)) in
  let names = texts_col "file" (List.map ~f:fst stats) in
  let total = intgr_col "total" (of_stats Q.total) in
  let relat kind s = Q.relat s kind in
  let prcnt = List.map
      ~f:(fun (name, f) -> float_col name (of_stats f))
             [ "successful, %",   relat `Success;
               "unsound, %", relat `Unsound_sema;
               "undisas, %",  relat `Disasm_error;
               "unknown, %",   relat `Unknown_sema; ] in
  let tab = hcat ~sep:(text "  |  ") ([cnter; names; total] @ prcnt) in
  Out_channel.output_string out (render tab);
  Out_channel.close out
