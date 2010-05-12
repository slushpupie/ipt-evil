
ALL_EXEC = ipt_evil
CFLAGS=-Wall -g

ipt_evil: ipt_evil.o 
	$(CC) -o $@ ipt_evil.o -lipq 
clean:
	$(RM) *.[ao] $(ALL_EXEC)


