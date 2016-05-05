# bil-verification

This tool compares the results of the execution in the trace with the
execution of our lifted IL. A central goal is to use this feature to
find errors in our lifting instructions, which happen when the
execution of the IL does not match that of the concrete instruction
trace. Verification is based on comparison of two set of events -
first one is a real events set, that came from trace. And second one 
is a set, that was filled during execution of `code_exec` event, by
emitting artificial events. 

##Policy

There is an ideal case when all events from trace and all events from
BIL are equal to each other. But in practice both trace and bil could
contain some special cases. For example, trace could be obtained from
source, that does not provide some cpu flags, or bil does not support
some instructions. And we possible may want to shadow this cases and
continue verification process. From other point of view, we do not want 
to miss errors. So for this reasons tool supports policy, that is a set
of rules with the following grammar.

Each rule consists of 4 fields, separated by `|` : 
`ACTION | INSN | EVENT | EVENT`
Action could be either `SKIP`, either `DENY`. If we processed all rules 
without matching with DENY, then everything is ok. Matching is performed 
textually, based on event syntax. Regexp syntax supports back references 
in event fields.

For example, let's imagine that a tracer doesn't support read from zero 
flag, so all read events from zero flag in bil code will be unmatched. 
So we are able to create next rule :
`SKIP| (.*) |   | ZF -> (.*)`
This could be read as: for any instruction skip unmatched zero flag 
reading in bil code.
Next two rules means that that no one should be left without a pair.
```
DENY | (.*) | (.*) | 
DENY | (.*) |   |  (.*)
```
That does mean that for any instruction unmatched left/right event
is an error.

Also we can use this policy to check incomplete lifter, for example we can say:
```
DENY: MOV(.*) : (.*) : 
DENY: MOV(.*) :   :  (.*)
```
And check only move instructions.

##Usage
```
./veri_main.native --verbose --rules "path to rules file" "path to trace file"
```
