-------------------------------- MODULE Network -------------------------------
EXTENDS Naturals, Sequences, SequencesExt, Functions, TLC

CONSTANT
    OrderedNoDup,
    Ordered,
    ReorderedNoDup,
    Reordered

CONSTANT
    Guarantee
ASSUME Guarantee \in {OrderedNoDup, Ordered, ReorderedNoDup, Reordered}

CONSTANT 
    Servers

VARIABLE 
    messages

----------------------------------------------------------------------------------
\* Reordering and duplication of messages:

LOCAL ReorderDupInitMessageVar ==
    messages = <<>>
    
LOCAL ReorderDupWithMessage(m, msgs) == 
    IF m \notin (DOMAIN msgs) THEN
        msgs @@ (m :> 1)
    ELSE
        [ msgs EXCEPT ![m] = @ + 1 ]

LOCAL ReorderDupWithoutMessage(m, msgs) == 
    IF msgs[m] = 1 THEN
        [ msg \in ((DOMAIN msgs) \ {m}) |-> msgs[msg] ]
    ELSE
        [ msgs EXCEPT ![m] = @ - 1 ]

LOCAL ReorderDupMessages ==
    DOMAIN messages

LOCAL ReorderDupMessagesTo(dest) ==
    { m \in ReorderDupMessages : m.dest = dest }

LOCAL ReorderDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderDupMessages /\ msg \in ReorderDupMessages'
    \/ msg \in ReorderDupMessages /\ messages'[msg] > messages[msg]

----------------------------------------------------------------------------------
\* Reordering and deduplication of messages (iff the spec removes message m from
\* msgs after receiving m, i.e., ReorderNoDupWithoutMessage.)

LOCAL ReorderNoDupInitMessageVar ==
    messages = {}

LOCAL ReorderNoDupWithMessage(m, msgs) == 
    msgs \union {m}

LOCAL ReorderNoDupWithoutMessage(m, msgs) == 
    msgs \ {m}

LOCAL ReorderNoDupMessages ==
    messages

LOCAL ReorderNoDupMessagesTo(dest) ==
    { m \in messages : m.dest = dest }

LOCAL ReorderNoDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderNoDupMessages /\ msg \in ReorderNoDupMessages'
    \/ msg \in ReorderNoDupMessages /\ messages'[msg] > messages[msg]

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and duplication of messages:

LOCAL OrderInitMessageVar ==
    messages = [ s \in Servers |-> <<>>]

LOCAL OrderWithMessage(m, msgs) ==
    [ msgs EXCEPT ![m.dest] = Append(@, m) ]

LOCAL OrderWithoutMessage(m, msgs) ==
    [ msgs EXCEPT ![m.dest] = SelectSeq(@, LAMBDA e: m # e) ]

LOCAL OrderMessages ==
    UNION { Range(messages[s]) : s \in Servers }

LOCAL OrderMessagesTo(dest) ==
    IF messages[dest] # <<>> THEN {messages[dest][1]} ELSE {}

LOCAL OrderOneMoreMessage(m) ==
    \/ /\ m \notin OrderMessages
       /\ m \in OrderMessages'
    \/ Len(SelectSeq(messages[m.dest], LAMBDA e: m = e)) < Len(SelectSeq(messages'[m.dest], LAMBDA e: m = e))

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and no duplication of messages:

LOCAL OrderNoDupInitMessageVar ==
    OrderInitMessageVar

LOCAL OrderNoDupWithMessage(m, msgs) ==
    IF \E i \in 1..Len(msgs[m.dest]) : msgs[m.dest][i] = m THEN
        msgs
    ELSE
        OrderWithMessage(m, msgs)

LOCAL OrderNoDupWithoutMessage(m, msgs) ==
    OrderWithoutMessage(m, msgs)

LOCAL OrderNoDupMessages ==
    OrderMessages

LOCAL OrderNoDupMessagesTo(dest) ==
    OrderMessagesTo(dest)

LOCAL OrderNoDupOneMoreMessage(m) ==
    \/ /\ m \notin OrderMessages
       /\ m \in OrderMessages'
    \/ /\ m \in OrderMessages
       /\ m \in OrderMessages'

----------------------------------------------------------------------------------

InitMessageVar ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupInitMessageVar
      [] Guarantee = Ordered        -> OrderInitMessageVar
      [] Guarantee = ReorderedNoDup -> ReorderNoDupInitMessageVar
      [] Guarantee = Reordered      -> ReorderDupInitMessageVar

Messages ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupMessages
      [] Guarantee = Ordered        -> OrderMessages
      [] Guarantee = ReorderedNoDup -> ReorderNoDupMessages
      [] Guarantee = Reordered      -> ReorderDupMessages

MessagesTo(dest) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupMessagesTo(dest)
      [] Guarantee = Ordered        -> OrderMessagesTo(dest)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupMessagesTo(dest)
      [] Guarantee = Reordered      -> ReorderDupMessagesTo(dest)

\* Helper for Send and Reply. Given a message m and set of messages, return a
\* new set of messages with one more m in it.
WithMessage(m, msgs) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupWithMessage(m, msgs)
      [] Guarantee = Ordered        -> OrderWithMessage(m, msgs)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupWithMessage(m, msgs)
      [] Guarantee = Reordered      -> ReorderDupWithMessage(m, msgs)

\* Helper for Discard and Reply. Given a message m and bag of messages, return
\* a new bag of messages with one less m in it.
WithoutMessage(m, msgs) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupWithoutMessage(m, msgs)
      [] Guarantee = Ordered        -> OrderWithoutMessage(m, msgs)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupWithoutMessage(m, msgs)
      [] Guarantee = Reordered      -> ReorderDupWithoutMessage(m, msgs)
   
OneMoreMessage(msg) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupOneMoreMessage(msg)
      [] Guarantee = Ordered        -> OrderOneMoreMessage(msg)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupOneMoreMessage(msg) 
      [] Guarantee = Reordered      -> ReorderDupOneMoreMessage(msg)

==================================================================================
