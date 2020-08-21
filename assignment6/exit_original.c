char *bye=
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x01"                    /* mov    $0x1,%al */
 "\x31\xdb"                    /* xor    %ebx,%ebx */
 "\xcd\x80";                   /* int    $0x80 */

int main(void)
{
		((void (*)(void)) bye)();
		return 0;
}