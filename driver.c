#include <pcy.h>
#undef PCY_STUB_ON
#define PCY_STUB_ON 1
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char * * argv)
{
	FILE *f;
	FILE *g;
	FILE *h;
	unsigned char *buf;
	unsigned int size, i;
	char mode = 0;
	pcy_cryptokey key;
	struct stat st;
	if (argc != 2 && argc != 5)
	{
		printf( "Keygen:  %s <keyfile>\n"
			"Encrypt: %s <keyfile> <outfile> <infile> -e\n"
			"Decrypt: %s <keyfile> <outfile> <infile> -d\n",
		      argv[0], argv[0], argv[0]);
		return 1;
	}
	if (argc == 2)
	{
		f = fopen(argv[1], "w");
		key = genkey();
		printkey(&key, f);
		printkeydata(key);
		fclose(f);
	}
	if (argc > 2)
	{
		f = fopen(argv[1], "r");
		g = fopen(argv[2], "w");
		h = fopen(argv[3], "r");
		
		fread(&key, sizeof(pcy_cryptokey), 1, f);
		printkeydata(key);

		stat(argv[3], &st);
		size = st.st_size;
		printf("Size: %d\n", size);
		buf = malloc(size * 2 + 15);
		
		for (i = 0; i < size; i++)
			fscanf(h, "%c", &buf[i]);
		fclose(h);
		
		if (argv[4][1] == 'd') mode = 1;
		
		do_crypt(key, buf, &size, mode);
		for (i = 0; i < size; i++)
			fprintf(g, "%c", buf[i]);
		fclose(f);
		fclose(g);
	}
	fclose(f);
}
