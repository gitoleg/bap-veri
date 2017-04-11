open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Std = struct
  module Traci   = Veri_traci
  module Chunki  = Veri_chunki
  module Disasm  = Veri_chunki.Disasm
  module Policy  = Veri_policy
  module Result  = Veri_result
  module Rule    = Veri_rule
  module Exec    = Veri_exec
  module Info    = Veri_exec.Info
end
