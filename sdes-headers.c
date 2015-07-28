

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


typedef struct program_arguments {
	char *d;
	char *init_key;
	char *init_vector;
	char *original_file;
	char *result_file;
} Arguments;
