open Core_kernel.Std
open OUnit2
open Bap.Std
open Bap_traces.Std
open Event

module Dis = Disasm_expert.Basic

let arch = `x86
let size = 32

let assert_false s = assert_bool s false

let word_of_int x = Word.of_int ~width:size x

let test_tool = 
  Trace.register_tool (module struct
    let name = "test tool"
    let supports tag = true
    let probe uri = false
  end)

let make_move cell' data' = Move.({cell = cell'; data = data';}) 

let make_reg var_name value = 
  let var = Var.create var_name (Type.Imm size) in
  let dat = word_of_int value in
  make_move var dat

let make_mem addr value = 
  make_move (word_of_int addr) (word_of_int value)

let make_chunk addr' data' = 
  Chunk.({addr = word_of_int addr'; data = data';}) 

let make_event tag value = Value.create tag value

let make_trace code real_evs = 
  let events = Seq.of_list (code::real_evs) in
  let trace = Trace.create test_tool in
  let trace = Trace.set_attr trace Meta.arch arch in
  Trace.append trace events 

let is_equal_events evs evs' =
  let is_exists ev = List.exists ~f:(fun ev' -> ev = ev') evs' in
  List.length evs = List.length evs' &&
  List.for_all ~f:is_exists evs

let eval_trace trace =
  Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
      let dis = Dis.store_asm dis |> Dis.store_kinds in          
      let report = Veri_report.create () in
      let ctxt = new Veri.context [] report trace in
      let veri  = new Veri.t arch dis (fun _ -> true) in
      let ctxt' = 
        Monad.State.exec (veri#eval_trace trace) ctxt in
      Ok ctxt'#report)

let hd_frames = function
  | [] -> None
  | (name, diffs) :: _ -> 
    match diffs with
    | [] -> None
    | hd ::_ -> Some (name, hd)

let check_trace pref trace expected =
  match eval_trace trace with 
  | Error er -> 
    let s = Printf.sprintf "%s: %s" pref (Error.to_string_hum er) in
    assert_false s 
  | Ok report ->
    match hd_frames (Veri_report.frames report) with 
    | None -> 
      let s = Printf.sprintf "%s: empty frames" pref in
      assert_false s
    | Some (name, (left,_)) ->
      let diff = Set.to_list left in
      let s = Printf.sprintf "%s: diff equality check" pref in
      assert_bool s (is_equal_events expected diff)

(** MOV32rr: { EAX := low:32[ESP] } *)
let test_reg ctxt = 
  let code = make_event code_exec (make_chunk 0xF67DE0D0 "\x89\xE0") in
  let e0 = make_event register_read (make_reg "EFLAGS" 0x202) in
  let e1 = make_event register_read (make_reg "EAX" 0x0) in
  let e2 = make_event register_read (make_reg "ESP" 0xF6FFEE50) in
  let e3 = make_event register_write (make_reg "EAX" 0xF6FFEE50) in
  let e4 = make_event register_write (make_reg "EFLAGS" 0x202) in
  let e5 = make_event pc_update (word_of_int 0xF67DE0D2) in
  let real_evs = [e0;e1;e2;e3;e4;e5;] in
  let trace = make_trace code real_evs in
  let expected_diff = [e0; e1; e4; e5] in
  check_trace "test_reg" trace expected_diff
      
(** MOV32mr: 
    { 
       mem32 := mem32 with 
             [(pad:32[low:32[EBP]]) + 0xFFFFFFBC:32, el]:u32 <- low:32[EAX]
    } *)
let test_mem_store ctxt =
  let code = make_event code_exec (make_chunk 0xF67E17D4 "\x89\x45\xBC") in
  let e0 = make_event register_read (make_reg "EFLAGS" 0x296) in
  let e1 = make_event register_read (make_reg "EBP" 0xF6FFEE48) in
  let e2 = make_event register_read (make_reg "EAX" 0xF6FFEE50) in
  let e3 = make_event memory_store (make_mem 0xF6FFEE04 0xF6FFEE50) in
  let e4 = make_event register_write (make_reg "EFLAGS" 0x296) in
  let e5 = make_event pc_update (word_of_int 0xF67E17D7) in
  let real_events = [e0;e1;e2;e3;e4;e5;] in
  let trace = make_trace code real_events in
  let expected_diff = [e0; e4; e5] in
  check_trace "test_mem_store" trace expected_diff

(** MOV32rm : { EBX := mem32[low:32[ESP], el]:u32 }*)
let test_mem_load ctxt = 
  let code = make_event code_exec (make_chunk 0xF67F57A8 "\x8B\x1C\x24") in
  let e0 = make_event register_read (make_reg "EFLAGS" 0x282) in
  let e1 = make_event register_read (make_reg "ESP" 0xF6FFEDDC) in
  let e2 = make_event memory_load (make_mem 0xF6FFEDDC 0xF67E17CE) in
  let e3 = make_event register_write (make_reg "EBX" 0xF67E17CE) in
  let e4 = make_event register_write (make_reg "EFLAGS" 0x282) in
  let e5 = make_event pc_update (word_of_int 0xF67F57AB) in
  let real_evs = [e0;e1;e2;e3;e4;e5;] in
  let trace = make_trace code real_evs in
  let expected_diff = [e0; e4; e5] in  
  check_trace "test_mem_load" trace expected_diff

let suite () =
  "Veri test reg" >:::
  [
    "reg test"        >:: test_reg;
    "mem store test"  >:: test_mem_store;
    "mem load test"   >:: test_mem_load;
  ]
  
