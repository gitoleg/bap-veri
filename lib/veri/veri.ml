open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

let () = printf "entering  Veri.Std\n"; flush stdout

module Std = struct
  type 'a u = 'a Bil.Result.u
  type event = Trace.event

  include Veri_types.Std
end
