open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

val update_db :
  ?compiler_ops:string list ->
  ?object_ops:string list ->
  ?extra:string ->
  Trace.t ->
  Veri_rule.t list ->
  Veri_numbers.t ->
  string -> unit Or_error.t
