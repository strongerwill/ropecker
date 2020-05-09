#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define YES 1
#define NO  0

unsigned long Hex2Ulong(char s[])
{
    int i;
    unsigned long n;
    int inhex, digital;

    i = 0;
    if (s[i] == '0')
    {
        i++;
        if (s[i] == 'x' || s[i] == 'X')
        {
            i++;
        }
    }

    n = 0;
    inhex = YES;
    for (; inhex == YES; i++)
    {
        if (s[i] >= '0' && s[i] <= '9')
            digital = s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'f')
            digital = s[i] - 'a' + 10;
        else if (s[i] >= 'A' && s[i] <= 'F')
            digital = s[i] - 'A' + 10;
        else
        {
            inhex = NO;
            break;
        }
        n = 16 * n + digital;
    }

    return n;
}

#define BUFFER_SIZE				(4096)
#define BLOCK_SIZE				(4096)

int main(int argc, char **argv)
{
	FILE *pFile = NULL;
	void *paddr = NULL;

	char buffer[BUFFER_SIZE];
	char address[BUFFER_SIZE];
	char block[BLOCK_SIZE];

	char c;
	int i, ineedreset, iblocks, iSize;
	
	pFile = fopen("/proc/self/maps", "r");
	if (NULL == pFile)
	{
		printf("/proc/self/maps fopen failed, error!\r\n");
		return 1;
	}

	/* 查找vdso动态库映射内存位置  */
	i = 0;
	ineedreset = 1;
	memset(buffer, 0, BUFFER_SIZE);
	while(1) 
	{
		c = fgetc (pFile);
		if (c != EOF) 
		{
			printf("%c", c);
			if (c == '\r' || c == '\n')
			{
				i = 0;
				ineedreset = 1;
			} else
			{
				if (ineedreset)
				{
					if (NULL != strstr(buffer, "vdso"))
					{
						printf("I have got vdso section.\r\n");
						break;
					}
					memset(buffer, 0, BUFFER_SIZE);
					ineedreset = 0;
				}			
				buffer[i++] = c;
			}
		}else
		{
			break;
		}
    }

	printf("vsdo line is:%s\r\n", buffer);
	fclose(pFile);
	pFile = NULL;
	
	/* 获取起始地址 */
	memset(address, 0, BUFFER_SIZE);
	for (i = 0; buffer[i] != '-'; i++)
	{
		address[i] = buffer[i];
		if (buffer[i] == '-')
			break;
	}

	paddr = (void *) Hex2Ulong(address);
	printf("Current VDSO address is 0x%08lx\r\n", (ulong)paddr);
	iblocks = (unsigned long)paddr / BLOCK_SIZE;
	printf("We have %d blocks before VDSO library\r\n", iblocks);
	printf("Ready to generate linux-gate.dso from block %d\r\n", iblocks);

	/* 导出vdso动态文件 */
	pFile = fopen("./linux-gate.dso", "w");
	if (NULL == pFile)
	{
		printf("fopen linux-gate.dso failed, exit!\r\n");
		return 1;
	}

	printf("Head:0x%x-%c-%c-%c\r\n", *((char *)paddr + 0),*((char *)paddr + 1),*((char *)paddr + 2),*((char *)paddr + 3));
        memcpy(block, paddr, BLOCK_SIZE);
	iSize = fwrite(block, 1, BLOCK_SIZE, pFile);
	if (BLOCK_SIZE != iSize)
	{
		perror("fwrite error:\r\n");
	}
	printf("copy %d/%d bytes from 0x%08lx to the file\r\n", iSize, BLOCK_SIZE, (ulong)paddr);

	fclose(pFile);
	printf("Generate linux-gate.dso Done\r\n");

	return 0;
}
