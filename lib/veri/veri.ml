open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Std = struct

  type 'a u = 'a Bil.Result.u
  type event = Trace.event

  module Traci   = Veri_traci
  module Chunki  = Veri_chunki
  module Disasm  = Chunki.Disasm
  module Policy  = Veri_policy
  module Result  = Veri_result
  module Rule    = Veri_rule
  module Exec    = Veri_exec
  module Info    = Exec.Info
  module Backend = Veri_backend
end
