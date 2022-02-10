# Exception Ret Spoofing
A simple and minimalistic way to spoof return addresses using an exception handler

# Pros & Cons
Pros:
* Very easy to implement
* Very easy to use
* Can easily be used with other exceptions/gadgets

Cons:
* Very slight but noticeable performance decrease when used in loops or frequently called hooks
* Relies on the preservation of the nonvolatile GPRs of the x64 calling convention
  * Which in this case means it expects these registers to be preserved, in very rare cases they might not be
  * Read [MSDN Documentation for Caller/Callee Saved registers](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#callercallee-saved-registers)
  
# Results
![Successful_Call](https://github.com/Peribunt/Exception-Ret-Spoofing/blob/main/MsgBoxCall.jpg?raw=true)
![Successful Return](https://github.com/Peribunt/Exception-Ret-Spoofing/blob/main/MsgBoxResult.jpg?raw=true)
