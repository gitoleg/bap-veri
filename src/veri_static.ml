open Core_kernel.Std
open Bap.Std

include Self()

let update_static db proj =
  let insns = Disasm.insns @@ Project.disasm proj in
  let r =
    Veri_db.update_with_static
      ~name:"" (Project.arch proj) insns db in
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

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        let db = !db in
        Project.register_pass' (update_static db))
end
