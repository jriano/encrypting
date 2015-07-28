/***
	This program encrypts and decrypts a file.
	Juan C. Riano
*/

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>

static struct sigaction sa;  		// hancle ctr-c  

typedef unsigned char unchar;
typedef unsigned int unint;
typedef struct program_arguments {
	int d;
	unint init_key;
	unint init_vector;
	char *original_file;
	char *result_file;
} Arguments;

unchar publicVal1 = 0, publicVal2 = 0;

/************************************ Function Prototypes *****************************************/

//Key Generation
unchar genKey1(unint key10bits);
unchar genKey2(unint key10bits);
unint p10(unint key10bits);
unchar p8(unint key10bits);
unint cls1bit(unint key10bits);
unint cls2bits(unint key10bits);

//	S-DES Encryption
unchar sdesEncrypt(unchar text8bits, unint key10bits);
unchar sdesDecrypt(unchar cipher8bits, unchar key10bits);
unchar fk(unchar text8bits, unchar key8bits);
unchar initialPerm(unchar text8bits);
unchar inversePerm(unchar text8bits);
unchar bigF(unchar right, unchar sk);
unchar bigFexpansion(unchar right);
unchar get4fromBxs(unchar input);
unchar getP0c(unint input);
unchar getP1c(unint input);
unchar p4(unchar input);
unchar switch4(unchar text8bits);

//	CBC Encription / Decription
void cbcEncript(unchar vector, unint key10bits, char *inputFileName, char *outputFileName);
void cbcDecript(unchar vector, unint key10bits, char *inputFileName, char *outputFileName);

// Miscelaneous - helpers
void setSignalVars(void);
void sigInt(int signal);
void dieWithMssg(char *msg);
unint strBinaryToInt(char *binary);
void checkArgs(int argc, char *argv[]);
void parseArgs(int argc, char *argv[], Arguments *args);

/******************************************** Main ************************************************/

int main(int argc, char *argv[]) {
	setSignalVars();
	checkArgs(argc, argv);
	
	Arguments args;
	parseArgs(argc, argv, &args);
	//if(args.d == 0) 
		//cbcEncript(args.init_vector, args.init_key, args.original_file, args.result_file);
		//cbcEncript(170, 627, "war-and-peace.txt", "war-and-peace2.txt");
		cbcEncript(1, 1, "war-and-peace.txt", "war-and-peace2.txt");
	//else
		//cbcDecript(args.init_vector, args.init_key, args.original_file, args.result_file);
		//cbcDecript(170, 627, "war-and-peace2.txt", "war-and-peace3.txt");
		cbcDecript(1, 1, "war-and-peace2.txt", "war-and-peace3.txt");

			// unchar vector = 170;
			// unchar text8bits = 1;
			// unchar text8bits2 = 35;			
			// unint key = 509;



			// text8bits = text8bits ^ vector;
			// unchar res1 = sdesEncrypt(text8bits, key);
			// printf("RESULT 1: %d SHOULD BE 244\n", res1);

			// text8bits = res1 ^ text8bits2;
			// unchar res2 = sdesEncrypt(text8bits, key);
			// printf("result 2: %d SHOULD BE 11\n", res2);
	return 0;
}



/*************************************** Key Generation *******************************************/

/*	genKey1: Takes a 2 bytes unsigned integer, and uses only the least significant 10 bits to 
	generate an 8-bit key using the S-DES algorithm. */
unchar genKey1(unint key10bits) {
	return p8(cls1bit(p10(key10bits)));
}

/*	genKey2: Takes a 2 bytes unsigned integer, and uses only the least significant 10 bits to 
	generate an 8-bit key using the S-DES algorithm. */
unchar genKey2(unint key10bits) {
	return p8(cls2bits(cls1bit(p10(key10bits))));
}

/* 	p10: Permutes the 10-bit key as defined by the S-DES algorithm. */
unint p10(unint key10bits) {
	unint key, i;
	unint mask = 0;	
	unint arr[10];
	memset(arr, 0, sizeof(arr)); 
	
	mask = 1; key = key10bits;
	arr[0] = mask & (key >> 4);

	mask = 2; key = key10bits;
	arr[1] = mask & (key >> 1);

	mask = 4; key = key10bits;
	arr[2] = mask & (key << 1);

	mask = 8; key = key10bits;
	arr[3] = mask & (key >> 6);

	mask = 16; key = key10bits;
	arr[4] = mask & (key << 4);

	mask = 32; key = key10bits;
	arr[5] = mask & (key >> 1);

	mask = 64; key = key10bits;
	arr[6] = mask & (key << 3);

	mask = 128; key = key10bits;
	arr[7] = mask & (key >> 1);

	mask = 256; key = key10bits;
	arr[8] = mask & (key << 3);

	mask = 512; key = key10bits;
	arr[9] = mask & (key << 2);

	key = 0;
	for(i=0; i<10; i++) 
		key = key | arr[i];
	return key;
}

/*	p8: Takes two+ bytes, and operates on the 10 most significant bots to 
	produce an 8-bit key based on the SDES algorithm. */
unchar p8(unint key10bits) {
	unint key, i;
	unint mask = 0;	
	unint arr[8];
	memset(arr, 0, sizeof(arr)); 
	
	mask = 1; key = key10bits;
	arr[0] = mask & (key >> 1);

	mask = 2; key = key10bits;
	arr[1] = mask & (key << 1);

	mask = 4; key = key10bits;
	arr[2] = mask & (key >> 3);

	mask = 8; key = key10bits;
	arr[3] = mask & (key << 1);

	mask = 16; key = key10bits;
	arr[4] = mask & (key >> 2);

	mask = 32; key = key10bits;
	arr[5] = mask & (key << 2);

	mask = 64; key = key10bits;
	arr[6] = mask & (key >> 1);

	mask = 128; key = key10bits;
	arr[7] = mask & (key << 3);

	key = 0;
	for(i=0; i<8; i++) 
		key = key | arr[i];
	return key;	
}

/*	1 bit Circular Left Shift of two 5-bit blocks:
	Takes an unint, but works only with the 10 least significant bits, divides
	those 10 bits in two 5-bit groups, and do a circular left shift of their bits. */
unint cls1bit(unint key10bits) {
	unint block, leftBit, key = 0;

	// rotate left most block of bits
	block = key10bits & 992;
	leftBit = block & 512;
	block = (block << 1) & 992;
	leftBit = leftBit >> 4;
	key = block | leftBit;

	//rotate right block of bits
	block = key10bits & 31;
	leftBit = block & 16;
	block = (block << 1) & 31;
	leftBit = leftBit >> 4;
	return key | block | leftBit;
}

/*	2 bits Circular Left Shift of two 5-bit blocks:
	Takes an unint, but works only with the 10 least significant bits, divides
	those 10 bits in two 5-bit groups, and do a circular left shift of their bits. */
unint cls2bits(unint key10bits) {
	unint block, left2Bits, key = 0;

	// rotate left most block of bits
	block = key10bits & 992;
	left2Bits = block & 768;
	block = (block << 2) & 992;
	left2Bits = left2Bits >> 3;
	key = block | left2Bits;

	//rotate right block of bits
	block = key10bits & 31;
	left2Bits = block & 24;
	block = (block << 2) & 31;
	left2Bits = left2Bits >> 3;
	return key | block | left2Bits;
}

/************************************ S-DES Encryption ********************************************/

/* 	sdesEncrypt: Takes an 8-bit block of data and a 10-bit key and produces an 
	8-bit block	of ciphertext. 
	ciphertext = negIP ( Fk2 ( SW ( Fk1 ( IP )))). */
unchar sdesEncrypt(unchar text8bits, unint key10bits) {
	unchar key1 = genKey1(key10bits);
	unchar key2 = genKey2(key10bits);
	return inversePerm(fk(switch4(fk(initialPerm(text8bits), key1)), key2));
}

/*	sdesDecrypt: Takes 8 bits of ciphertext and the same 10-bit key, and 
	produces the original 8-bits of plaintext. 
	plaintext = negIP ( Fk1 ( SW ( Fk1 ( IP )))). */
unchar sdesDecrypt(unchar cipher8bits, unchar key10bits) {
	unchar key1 = genKey1(key10bits);
	unchar key2 = genKey2(key10bits);
	return inversePerm(fk(switch4(fk(initialPerm(cipher8bits), key2)), key1));
}

/*	fk: Do permutation and substitution.
	Uses an 8-bit key and an 8-bit text block to generate an 8-bit cypher text. */
unchar fk(unchar text8bits, unchar key8bits) {
	unchar temp = bigF(text8bits, key8bits);
	unchar temp2 = temp << 4;
	unchar left = (   text8bits ^  temp2  ) & 240;
	//unchar left = (text8bits ^ (bigF(text8bits, key8bits) << 4)) & 240;	
	// unchar left = text8bits;
	unchar right = text8bits & 15;
	unchar result = left | right;
	//printf("\nbigF -- text8bits %d -- temp: %d -- temp2: %d -- left %d -- right %d -- result %d\n"
	//	,text8bits, temp, temp2, left, right, result);
	return result;
}

/*	initialPerm: Takes 8 bits of plaintext, do some permutation as defined in the
	S-DES algorithm, and returns the scrambled 8 bits. */
unchar initialPerm(unchar text8bits) {
	unint key, i;
	unint mask = 0;	
	unint arr[8];
	memset(arr, 0, sizeof(arr)); 
	
	mask = 1; key = text8bits;
	arr[0] = mask & (key >> 1);

	mask = 2; key = text8bits;
	arr[1] = mask & (key >> 2);

	mask = 4; key = text8bits;
	arr[2] = mask & (key << 2);

	mask = 8; key = text8bits;
	arr[3] = mask & (key >> 1);

	mask = 16; key = text8bits;
	arr[4] = mask & (key >> 3);

	mask = 32; key = text8bits;
	arr[5] = mask & (key << 0);

	mask = 64; key = text8bits;
	arr[6] = mask & (key << 4);

	mask = 128; key = text8bits;
	arr[7] = mask & (key << 1);

	key = 0;
	for(i=0; i<8; i++) 
		key = key | arr[i];
	return key;	
}

/*	inversePerm: a permutation function inverse of initialPerm. */
unchar inversePerm(unchar text8bits) {
	unint key, i;
	unint mask = 0;	
	unint arr[8];
	memset(arr, 0, sizeof(arr)); 
	
	mask = 1; key = text8bits;
	arr[0] = mask & (key >> 2);

	mask = 2; key = text8bits;
	arr[1] = mask & (key << 1);

	mask = 4; key = text8bits;
	arr[2] = mask & (key >> 4);

	mask = 8; key = text8bits;
	arr[3] = mask & (key << 2);

	mask = 16; key = text8bits;
	arr[4] = mask & (key << 1);

	mask = 32; key = text8bits;
	arr[5] = mask & (key << 0);

	mask = 64; key = text8bits;
	arr[6] = mask & (key >> 1);

	mask = 128; key = text8bits;
	arr[7] = mask & (key << 3);

	key = 0;
	for(i=0; i<8; i++) 
		key = key | arr[i];
	return key;	
}

/*	bigF: Acts on the right 4 most bits of a byte, and one one of the two keys 
	previously generated. */
unchar bigF(unchar right, unchar sk) {
	unchar expan = bigFexpansion(right);	// expand the right 4 bits
	unchar xored = expan ^ sk;				// perform XOR
	unchar fourBits = get4fromBxs(xored);
	return p4(fourBits);
}

/*	bigFexpansion: Takes one byte, works on the right most 4 bits to perform an 
	expansion as defined by the S-DES algorithm. */
unchar bigFexpansion(unchar right) {
	unchar rr = right;
	unchar ll = right;
	unchar helper = 0;

	// work on the far right part of the byte
	helper = (8 & right) >> 3;	// helper only has now leftmost bit on the far right
	rr = (rr << 1) & 14;		// moved and removed leftmost bit
	rr = rr | helper;			// right 4 bits ready!

	// work on the left 4 bits
	helper = (right & 1) << 7;	// helper only one bit set, right most moved to far left
	ll = (ll << 3) & 112;		// moved to the left, and kept 3 bits only
	ll = ll | helper;			// left 4 bits done!
	return ll | rr;
}

/*	get4fromBxs: Takes 8 bits, and use them to feed the 2 boxes and come up with
	a set of 4 bits that are returned in a byte, in which only the 
	least significant bits contain the return value, the rest is padded with 0's. */
unchar get4fromBxs(unchar input) {
	unint S0[4][4] = {	{1, 0, 3, 2}, 
						{3, 2, 1, 0}, 
						{0, 2, 1, 3}, 
						{3, 1, 3, 2}};
	unint S1[4][4] = {	{0, 1, 2, 3}, 
						{2, 0, 1, 3}, 
						{3, 0, 1, 0}, 
						{2, 1, 0, 3}};

	unchar p0c = getP0c(input);	
	unchar p0r = (input & 96) >> 5;
	unchar p1c = getP1c(input);
	unchar p1r = (input & 6) >> 1;
	unchar first2 = S0[p0c][p0r] << 2;
	unchar last2 = S1[p1c][p1r];
	return first2 | last2;
}

/*	getP0c: From an input byte, calculates the column of the P0 */
unchar getP0c(unint input) {
	unchar p0c = (input & 144) >> 4;
	unchar helper = (p0c & 8) >> 2;	
	p0c = p0c & 1;
	unchar result = p0c | helper;	
	return p0c | helper;
}

/*	getP1c: From an input byte, calculates the column of the P1 */
unchar getP1c(unint input) {
	unchar helper = (input & 8) >> 2;
	unchar p1c = input & 1;
	return p1c | helper;
}

/*	p4: Last permutation performed inside bigF. */
unchar p4(unchar input) {
	unchar one = (input & 8) >> 3;
	unchar two = (input & 4) << 1;
	unchar four = (input & 1) << 2;
	return (input & 2) | one | two | four;
}

/* switch4: Switches the left most 4 bits for the right most 4 bits */
unchar switch4(unchar text8bits) {
	unchar helper = (text8bits & 240) >> 4;
	return (text8bits << 4) | helper;
}

/********************************** CBC Encription / Decription ***********************************/

/*	Encripts a file using the S-DES algorithm in the Cipher Block Chaining mode. It takes an initial
	8-bit initialization vector, a 10-bits key, an input and output file name. */
// void cbcEncript(unchar vector, unint key10bits, char *inputFileName, char *outputFileName) {
// 	printf("vector: %d\n", vector);
// 	printf("key10bits: %d\n", key10bits);

// 	FILE *inputFile = NULL, *outputFile = NULL;
// 	unchar text8bits, previousCifer8bits, encripted8bits;
// 	int firstTime = 1;

// 	inputFile = fopen(inputFileName, "rb+");
// 	if(NULL == inputFile) perror("Could not open input file to encrypt");
// 	outputFile = fopen(outputFileName, "w+");
// 	if(NULL == outputFile) perror("Could not open output file while encrypting");

// 	while(fread(&text8bits, sizeof(unchar), 1, inputFile)) {
// 		if(firstTime) {
// 			firstTime = 0;
// 			text8bits = text8bits ^ vector;
// 		}
// 		else text8bits = text8bits ^ previousCifer8bits;

// 		previousCifer8bits = encripted8bits = sdesEncrypt(text8bits, key10bits);
// 		fwrite(&encripted8bits, sizeof(unchar), 1, outputFile);
// 	}
// 	fclose(inputFile);
// 	fclose(outputFile);
// }



void cbcEncript(unchar vectorr, unint key10bitss, char *inputFileName, char *outputFileName) {
	//printf("vector: %d\n", vector);
	//printf("key10bits: %d\n", key10bits);

	//FILE *inputFile = NULL, *outputFile = NULL;
	unchar text8bits, previousCifer8bits, encripted8bits;
	int firstTime = 1;

	// inputFile = fopen(inputFileName, "rb+");
	// if(NULL == inputFile) perror("Could not open input file to encrypt");
	// outputFile = fopen(outputFileName, "w+");
	// if(NULL == outputFile) perror("Could not open output file while encrypting");

		unchar vector = 170;
		text8bits = 1;
		unint key10bits = 509;

		printf("Values to encript: 1, 35\n\n");

		printf("\n\ntext: %u, vector: %u\n", text8bits, vector);
		text8bits = text8bits ^ vector;
		printf("after xor: %u\n\n", text8bits);
		publicVal1 = previousCifer8bits = encripted8bits = sdesEncrypt(text8bits, key10bits);

		text8bits = 35;
		text8bits = text8bits ^ previousCifer8bits;

		publicVal2 = previousCifer8bits = encripted8bits = sdesEncrypt(text8bits, key10bits);

		printf("Value1 = %u -- value2 = %u\n", publicVal1, publicVal2);

	// fclose(inputFile);
	// fclose(outputFile);
}





/*	Decripts a file using the S-DES algorithm in the Cipher Block Chaining mode. It takes an initial
	8-bit initialization vector, a 10-bits key, an input and output file name. */
// void cbcDecript(unchar vector, unint key10bits, char *inputFileName, char *outputFileName) {
// 	FILE *inputFile = NULL, *outputFile = NULL;
// 	// unchar cipher8bits, previousCipher8bits, encripted8bits;
// 	// int firstTime = 1;
// 	unchar cipher8bits, previousCipher8bits, text8bits;
// 	int firstTime = 1;

// 	inputFile = fopen(inputFileName, "rb+");
// 	if(NULL == inputFile) perror("Could not open input file to decrypt");
// 	outputFile = fopen(outputFileName, "w+");
// 	if(NULL == outputFile) perror("Could not open output file while decrypting");

// 	// while(fread((void *)&cipher8bits, sizeof(unchar), 1, inputFile)) {
// 	// 	if(firstTime) {
// 	// 		firstTime = 0;
// 	// 		cipher8bits = cipher8bits ^ vector;
// 	// 	}
// 	// 	else cipher8bits = cipher8bits ^ previousCipher8bits;

// 	// 	previousCipher8bits = encripted8bits = sdesDecrypt(cipher8bits, key10bits);
// 	// 	fwrite(&encripted8bits, sizeof(unchar), 1, outputFile);
// 	// }


// 	while(fread((void *)&cipher8bits, sizeof(unchar), 1, inputFile)) {
// 		previousCipher8bits = cipher8bits;
// 		text8bits = sdesDecrypt(cipher8bits, key10bits);

// 		if(firstTime) {
// 			firstTime = 0;
// 			text8bits = text8bits ^ vector;
// 		}
// 		else text8bits = text8bits ^ previousCipher8bits;
// 		fwrite(&text8bits, sizeof(unchar), 1, outputFile);
// 	}


// 	fclose(inputFile);
// 	fclose(outputFile);
// }



void cbcDecript(unchar vectorr, unint key10bitss, char *inputFileName, char *outputFileName) {

	unchar cipher8bits, previousCipher8bits, text8bits;


		unchar vector = 170;
		unint key10bits = 509;


		printf("Will now decript %u and %u\n\n", publicVal1, publicVal2);
		previousCipher8bits = cipher8bits = publicVal1;
		text8bits = sdesDecrypt(cipher8bits, key10bits);


		text8bits = text8bits ^ vector;
		printf("firt decripted output %d   --  ", text8bits);

		cipher8bits = publicVal2;
		text8bits = sdesDecrypt(cipher8bits, key10bits);

		text8bits = text8bits ^ previousCipher8bits;

		//NOW *****************************
		previousCipher8bits = cipher8bits;

		printf("second decripted output %d\n", text8bits);




}






/********************************** Miscelaneous  - helpers ***************************************/

/*	Sets the values for the ctrl-c handler */
void setSignalVars(void) {
    sa.sa_handler = sigInt;  
    sa.sa_flags = 0;          
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
}

/*  Quits the program on ctrl-C */
void sigInt(int signal) {
    printf("\n\nClosing program (ctrl-C detected)\n\n");
    exit(EXIT_SUCCESS);
}

/*	Prints a message and quits the Program */
void dieWithMssg(char *msg) { 
 	printf("%s\n", msg); 
 	exit(EXIT_FAILURE); 
}

unint strBinaryToInt(char *binary) {
	char *str = binary;
	unint i, anInt = 0;
	char bit = '\0';
	int len, len2; len = len2 = strlen(str);
	//printf("String: %s\n", str);
	//printf("len = %d\n", len);
	for(i=0; i<len; i++) {
		memcpy(&bit, str++, sizeof(char));
		//printf("bit is: %d\n", atoi(&bit));
		anInt = anInt + atoi(&bit) * pow(2, len2-1);
		//printf("anInt = %d\n", anInt);
		len2--;
	} 
	return anInt;
}

/*	Checks for correctnes of arguments provided to program */
void checkArgs(int argc, char *argv[]) {
	if (argc < 5 | argc > 6) 	{	
		printf("Usage: ./mycipher [-d] <init_key> <init_vector> <original_file> <result_file>\n");
		dieWithMssg("Please check your arguments and try again");
	}
}

void parseArgs(int argc, char *argv[], Arguments *args) {
	int argnum = 1;
	if(argc == 6) { args->d = 1; argv[argnum++]; }
	else args->d = 0;
	args->init_key = strBinaryToInt(argv[argnum++]);
	args->init_vector = strBinaryToInt(argv[argnum++]);
	args->original_file = malloc(sizeof(char *));
	args->original_file = argv[argnum++];
	args->result_file = malloc(sizeof(char *));
	args->result_file = argv[argnum];
	// printf("d = %d\n", args->d);
	// printf("key = %d\n", args->init_key);
	// printf("vector = %d\n", args->init_vector);
	// printf("original file = %s\n", args->original_file);
	// printf("result file = %s\n", args->result_file);
}



// typedef struct program_arguments {
// 	int d;
// 	unint init_key;
// 	unint init_vector;
// 	char original_file[100];
// 	char result_file[100];
// } Arguments;