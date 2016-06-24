open Core_kernel.Std
open Veri_policy

let comments = "//"
let rex = Pcre.regexp "'.*?'|\".*?\"|\\S+"

let is_quote c = c = '\"' || c = '\''
let unquote s = String.strip ~drop:is_quote s
let ok r = Ok r 
let er s = Error (Error.of_string s) 

let fields_exn str = 
  Pcre.exec_all ~rex str |>
  Array.fold ~init:[] ~f:(fun acc ar ->
      let subs = Pcre.get_substrings ar in
      acc @ Array.to_list subs) |>
  List.map ~f:unquote
    
let fields_opt str = 
  try
    match fields_exn str with 
    | [action; insn; left; right] -> Some (action, insn, left, right)
    | _ -> None
  with Not_found -> None

let fields_err str = 
  match fields_opt str with
  | Some fields -> ok fields
  | None -> 
    er (Printf.sprintf "String %s doesn't match to rule grammar" str)

let action_err = function 
  | "SKIP" -> ok Rule.skip
  | "DENY" -> ok Rule.deny
  | s -> er (Printf.sprintf "only SKIP | DENY actions should be used: %s" s)

let rule_of_string s = 
  let open Or_error in
  fields_err s >>= fun (action, insn, left, right) ->
  action_err action >>= fun action' ->
  ok (Rule.create ~insn ~left ~right action')

let is_interesting s = 
  s <> "" && not (String.is_prefix ~prefix:comments s)

let read fname = 
  let inc = In_channel.create fname in
  let strs = In_channel.input_lines inc in
  In_channel.close inc;
  List.map ~f:String.strip strs 
  |> List.filter ~f:is_interesting 
  |> List.map ~f:rule_of_string 


  
