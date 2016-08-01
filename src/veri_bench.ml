open Core_kernel.Std
open Core_bench.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std

module Dis = Disasm_expert.Basic

let () = 
  match Plugins.load () |> Result.all with
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s" 
      path (Error.to_string_hum er)

module Veri_bench_options = struct
  type t = {
    filter : string option;
    path : string;
  } [@@deriving fields]
end

module type Opts = sig
  val options : Veri_bench_options.t
end

module Program (O : Opts) = struct
  open Veri_bench_options
  open O

  let make_filter () = match options.filter with
    | None -> fun _ -> true 
    | Some fname -> 
      let is_sensible s = s <> "" in
      let inc = In_channel.create fname in
      let strs = In_channel.input_lines inc in
      In_channel.close inc;
      List.map ~f:String.strip strs
      |> List.filter ~f:is_sensible |>
      List.fold ~init:String.Set.empty ~f:String.Set.add |>
      Set.mem

  let string_of_error = function
    | `Protocol_error er -> 
      Printf.sprintf "protocol error: %s" 
        (Info.to_string_hum (Error.to_info er))
    | `System_error er -> 
      Printf.sprintf "system error: %s" (Unix.error_message er)
    | `No_provider -> "no provider"
    | `Ambiguous_uri -> "ambiguous uri"

  let prepare_insns dis arch trace =
    let endian = Arch.endian arch in
    let filter = make_filter () in
    let memory_of_chunk chunk = 
      Bigstring.of_string (Chunk.data chunk) |>
      Memory.create endian (Chunk.addr chunk) in
    let get_err tag ev = match Value.get tag ev with
      | None -> Error (Error.of_string "wrong tag")
      | Some v -> Ok v in
    let get_insn ev = 
      let open Or_error in
      get_err Event.code_exec ev >>= fun chunk ->
      memory_of_chunk chunk >>= fun mem ->
      Dis.insn_of_mem dis mem in
    let rec loop insns events = match Sequence.next events with
      | None -> insns
      | Some (ev, evs) -> match get_insn ev with
        | Error _ -> loop insns evs
        | Ok (mem', Some insn, `finished) ->
          if filter (Dis.Insn.name insn) then
            loop ((mem', insn) :: insns) evs
          else loop insns evs 
        | _ -> loop insns evs in
    loop [] (Trace.read_events trace)

  let lift_of_arch arch = 
    let module Target = (val target_of_arch arch) in
    Target.lift 

  let lift_insns f insns =
    List.iter ~f:(fun (mem, insn) -> 
        match f mem insn with 
        | Ok bil -> ()
        | Error er -> Printf.eprintf "%s\n" (Error.to_string_hum er)) insns
      
  let main () = 
    let uri = Uri.of_string ("file:" ^ options.path) in
    match Trace.load uri with
    | Error er -> 
      Printf.eprintf "error during loading trace: %s\n" (string_of_error er)
    | Ok trace ->
      match Dict.find (Trace.meta trace) Meta.arch with
      | None -> Printf.eprintf "trace of unknown arch"
      | Some arch ->
        let lift = lift_of_arch arch in
        Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
            let dis = Dis.store_asm dis |> Dis.store_kinds in
            Ok (prepare_insns dis arch trace)) |> function 
        | Error er -> Printf.printf "%s\n" (Error.to_string_hum er) 
        | Ok insns ->
          Bench.(bench [Test.create ~name:"Lift" (fun () -> lift_insns lift insns);])

end

module Command = struct

  open Cmdliner
      
  let filename = 
    let doc = "Input file with extension .frames" in 
    Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"FILE | DIR") 
      
  let insns_set, insns =
    let name = "insns-set" in
    let doc = "File with prefered instructions" in
    Arg.(value & opt (some non_dir_file) None & info [name] ~docv:"FILE" ~doc), 
    name

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Benchmarks for BAP lifters";
    ] in
    Term.info "veri" ~doc ~man

  let create a b = Veri_bench_options.Fields.create a b

  let run_t = Term.(const create $ insns_set $ filename)

  let filter_argv argv = 
    let ours = [ insns; ] in
    let prefix = "--" in
    let is_our arg =      
      if String.is_prefix arg ~prefix then
        List.exists ours ~f:(fun a -> prefix ^ a = arg) 
      else true in
    Array.filter ~f:is_our argv

  let parse argv = 
    let argv = filter_argv argv in
    match Term.eval ~argv (run_t, info) ~catch:false with
    | `Ok opts -> opts
    | `Error `Parse -> exit 64
    | `Error _ -> exit 2
    | _ -> exit 1

end

let start options =
  let module Program = Program(struct
      let options = options
    end) in
  Program.main ()

let () = start (Command.parse Sys.argv)

