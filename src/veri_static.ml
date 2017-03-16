open Core_kernel.Std
open Bap.Std

include Self()

let print_segments p =
  Project.memory p |> Memmap.to_sequence |> Seq.iter ~f:(fun (mem,x) ->
      Option.iter (Value.get Image.segment x) ~f:(fun seg ->
          if Image.Segment.is_executable seg then
            Format.printf "%a %a\n"
              Addr.pp (Memory.min_addr mem)
              Addr.pp (Memory.max_addr mem)))

let find_exec_bounds p =
  printf "called find\n";
  Project.memory p |> Memmap.to_sequence
  |> Seq.fold ~init:[] ~f:(fun mems (mem,x) ->
      match Value.get Image.segment x with
      | None -> mems
      | Some seg ->
        printf " has a segment %s!\n" (Image.Segment.name seg);
        if Image.Segment.is_executable seg then
          (Memory.min_addr mem, Memory.max_addr mem) :: mems
        else mems)

let update_static db name proj =
  let insns = Disasm.insns @@ Project.disasm proj in
  let mems = find_exec_bounds proj in
  let r =
    Veri_db.update_with_static
      ~name (Project.arch proj) mems insns db in
  match r with
  | Ok () -> ()
  | Error er -> eprintf "%s\n" @@  Error.to_string_hum er

module Cmdline = struct

  let man = [
    `S "DESCRIPTION";
    `P "Add a static information about given binary.";
  ]

  let db =
    let doc = "Path to database" in
    Config.(param string "db" ~doc)

  let name =
    let doc = "Path to database" in
    Config.(param string "name" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        Project.register_pass' (update_static !db !name))
end
