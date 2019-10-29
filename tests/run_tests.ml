open Core_kernel
open OUnit2
open Bap_main

let suite () =
  "Bap-veri" >::: [
    Veri_test.suite ();
    Veri_policy_test.suite ();
    Veri_rule_test.suite ();
    Veri_stat_test.suite ();
  ]

let () =
  let _ =
    match Bap_main.init ~name:"veri-runtests" ()
    with Ok () -> ()
       | Error err ->
          Format.eprintf "Program failed with: %a@\n%!"
            Extension.Error.pp err in
  run_test_tt_main (suite ())
