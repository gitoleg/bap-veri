open Core_kernel.Std
open Bap.Std
open Bap_future.Std
open Veri.Std

include Self ()

let header = "#, file, total, succeded %, unsound %, undisasmed %, unknown %\n"

let lines = ref 0

let init_lines path =
  if Sys.file_exists path then
    let ch = In_channel.create path in
    let n = In_channel.input_lines ch |> List.length in
    lines := max 0 (n - 1);
    In_channel.close ch

let run path =
  let () = init_lines path in
  fun proj ->
    let und = ref 0 in
    let uns = ref 0 in
    let unk = ref 0 in
    let suc = ref 0 in
    let of_info info = match Info.error info with
      | None -> incr suc
      | Some (kind,_) ->
        match kind with
        | `Unknown_sema -> incr unk
        | `Unsound_sema -> incr uns
        | `Disasm_error -> incr und in
    let print () =
      let out = Out_channel.create ~append:true path in
      let tot = !suc + !unk + !und + !uns in
      let rel x = float !x /. float tot *. 100.0 in
      let hd = if !lines = 0 then header else "" in
      let name = Uri.path (Proj.uri proj) in
      let s = sprintf "%s%d  %s  %d %.2f %.2f %.2f %.2f\n"
          hd !lines name tot (rel suc) (rel uns) (rel und) (rel unk) in
      Out_channel.output_string out s;
      Out_channel.close out in
    let infos, finish = Proj.info proj in
    Stream.observe infos of_info;
    Future.upon finish (fun () -> print (); incr lines)


module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Write a brief information about verification into file. ";
  ]

  let path =
    let doc = "File to output results" in
    Config.(param string "path" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} -> Backend.register (run !path))

end
