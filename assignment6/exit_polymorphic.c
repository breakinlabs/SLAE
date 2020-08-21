char *bye=
 "\x2b\xc0"                     /* xor    %eax,%eax */
 "\x40"                         /* mov    $0x1,%al */
 "\x2b\xdb"                     /* xor    %ebx,%ebx */
 "\xcd\x80";                    /* int    $0x80 */

int main(void)
{
		((void (*)(void)) bye)();
		return 0;
}