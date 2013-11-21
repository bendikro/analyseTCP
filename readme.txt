
Negative packet loss values when analysing sender and receiver dumps:
The packet loss is calculated by (sent packet - received packets).
When GSO is enabled on the sender, the sender dump may contain fewer
packets than the receiver dump.
