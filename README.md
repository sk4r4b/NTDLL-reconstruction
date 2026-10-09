# NTDLL-reconstruction
A userland EDR bypass technique that allows you to flip between unhooked and hooked ntdll.dll at will.
How I built this can be found [here](https://leosmith.wtf/blog/ntdll_reconstruction.html).

## Usage
You can just drag and drop the .h and .c file into your project make sure you
edit the header file definition for CRT functions that should either be reimplemented
by you or using whatever you want. You will also need to edit the switch_memory_protection
function inside of the .c file since you need to implement this yourself for the project
to work correctly.

Here is a snippet on how to use the lib:
```c
struct hook_cache	*cache = 0;

cache = ntdll_reconstruction_init();
if (cache == 0)
	// Throw Error!
while (1) {
	// Do whatever
	cache = ntdll_reconstruction_flip(cache); // Back to hooked stub
	if (cache == 0)
		// Throw Error!
	Sleep(1234);
	cache = ntdll_reconstruction_flip(cache); // Back to clean stub
	if (cache == 0)
		// Throw Error!
}
```


