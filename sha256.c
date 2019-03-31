	// Laura Ogba, 2019
	// The secure Hash Algorithm, 256 bit version
	// https://ws690.nist.gov/publication/get_pdf.cfm?pub_id=919060

	//The usual input/output header file.
	#include <stdio.h>
	// For using fixed-bit length integers.
	#include<stdint.h>

	// Represents a massage block.
	union msgblock{
		uint8_t e[64];
		uint32_t t[16];
		uint64_t s[8];
		};

	
	// Define the units for swapping big Edian to small Endian.
	#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
	#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)
	
	#define SWAP_UINT64(val) \
	( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
   	 (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
 	 (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
 	 (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )  

	// A flag for where we are in reading the file.
	enum status {READ, PAD0, PAD1, FINISH};

	//see section 4.1.2 for definitions.
	uint32_t sig0(uint32_t x);
	uint32_t sig1(uint32_t x);

	//see section 3.2 for definitions.
	uint32_t rotr(uint32_t n, uint32_t x);
	uint32_t shr(uint32_t n, uint32_t x);

	//see section 4.1.2 for definitions.
	uint32_t SIG0(uint32_t x);
	uint32_t SIG1(uint32_t x);

	//see section 4.1.2 for definitions
	uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
	uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

	// Calculates the SHA256 hash of a file.
	void sha256(FILE *f);

	// Retrieves the next message block
	int nextmsgblock(FILE * msgf, union msgblock *M, enum status *S, uint64_t  *nobits);


	
	// Start of the show.
	int main(int argc, char *argv[]){

	// Open the file given as first command line arguement.
	FILE  *msgf;
		
	if(argc !=2){
		printf("file not supplied..\n.");
	  	  return 0;
      	}
 
  		msgf= fopen(argv[1], "r");
  
  	if(msgf == NULL){
	      	printf("invalid file name\n");
		  return 1;
	}  
	


	// Run the secure hash algorithm on the file.
	sha256(msgf);	

	// Close the file.
	fclose(msgf);
				
	return 0;
	}


	void sha256(FILE *msgf){

	// The current message block	
	union msgblock M ;

	// The number of bits read from the file
	uint64_t nobits = 0;

	// The status of the message blocks, in terms of padding
	enum status S = READ;

	//The K constants defined in section 4.2.2.
	uint32_t K[] = {

		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

		};

	// Message schedule (Section 6.2).	
	uint32_t W[64];
	// Working Variables(section 6.2).
	uint32_t a, b, c, d, e, f, g, h;
	// Two temporary variables (section 6.2).
	uint32_t T1, T2;

	// The Hash Value
	// The values come from section 5.3.3
	uint32_t H[8] = {

		 0x6a09e667 ,0xbb67ae85
		,0x3c6ef372 ,0xa54ff53a
		,0x510e527f ,0x9b05688c
		,0x1f83d9ab ,0x5be0cd19
	
		};
		
	// For looping.
	int i, t;

	//Loop through the message blocks as per page 22.
	while (nextmsgblock(msgf, &M, &S, &nobits)) {

	// From page 22, W[t] = M[t]for 0 <= 15.
	for (t = 0; t < 16; t++)
		W[t] = SWAP_UINT32(M.t[t]);


	//From page 22, W[t] = ...
	for (t = 16; t < 64; t++)
		W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

	//Initialize a, b, c, d, e, f, g and h as per step 2, page 22.
	a = H[0]; b = H[1]; c = H[2]; d = H[3];
	e = H[4]; f = H[5]; g = H[6]; h = H[7];

	//step 3.
	for (t = 0; t < 64; t++){
		T1 = h + SIG1(e) + Ch(e, f, g) + K[t] + W[t];
		T2 = SIG0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = d;
		b = a;
		a = T1 + T2;
	
		}

	//step 4.
	H[0] = a + H[0]; H[1] = b + H[1];
	H[2] = c + H[2]; H[3] = d + H[3];
	H[4] = e + H[4]; H[5] = f + H[5];
	H[6] = g + H[6]; H[7] = h + H[7];

	}
	printf("\n");
	//printf("%08X%08X%08X%08X%08X%08X%08X%08X\n", H[0], H[1], H[3], H[4], H[5], H[6], H[7]);
	// Converting from big Endian to small Endian and vice versa
	if(IS_BIG_ENDIAN){
       		printf("%08x%08x%08x%08x%08x%08x%08x%08x\n",
				H[0], H[1],
				H[2], H[3], 
				H[4], H[5],
			       	H[6], H[7]);
	 }else{
		 printf("%08x%08x%08x%08x%08x%08x%08x%08x\n",
				 SWAP_UINT32(H[0]),
				 SWAP_UINT32(H[1]),
				 SWAP_UINT32(H[2]),
				 SWAP_UINT32(H[3]),
				 SWAP_UINT32(H[4]),
				 SWAP_UINT32(H[5]),
				 SWAP_UINT32(H[6]),
				 SWAP_UINT32(H[7]));
	 }
	}	

	
		
	//see section 3.2 for definitions.
	uint32_t rotr(uint32_t n, uint32_t x){
	return (x >> n) | (x << (32 - n));
	}

	uint32_t shr(uint32_t n, uint32_t x){
	return (x >> n);
	}


	uint32_t sig0(uint32_t x){
	// See section 3.2 for definitions and 4.1.2 also
	return (rotr(7, x) ^ rotr(18, x) ^ shr(3, x));
	}


	uint32_t sig1(uint32_t x){
	//see section 3.2 and 4.1.2 for definitions
	return (rotr(17,x) ^ rotr(19, x) ^ shr(10, x));
	}

	//see section 4.1.2 for definitions.
	uint32_t SIG0(uint32_t x){
	return (rotr (2, x) ^ rotr(13, x) ^ rotr(22, x));
	}
	uint32_t SIG1(uint32_t x){
	return (rotr (6, x) ^ rotr(11, x) ^ rotr(25, x));
	}

	//see section 4.1.2 for definitions
	uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
	return ((x & y) ^ ((~x) & z)); 
	}
	uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
	return ((x & y) ^ (x & z) ^ (y & z));
	}

	int nextmsgblock(FILE *msgf, union msgblock *M, enum status *S, uint64_t  *nobits) {
				
	// The number of bytes we get from fread.
	uint64_t nobytes;

	// For looping
	int i;

	// If we have finished all the message blocks, then S should be FINISH.
	if (*S == FINISH)
	return 0;

	// otherwise check if we need another block full of padding.
	if (*S == PAD0 || *S == PAD1){
	// Set the first 56 bytes to al zero bits.
	for (i = 0; i < 56; i++)
		M->e[i] = 0x00;
		// Set the last 64 bits to the number of bits in the file (should be big-endian).
		M->s[7] = SWAP_UINT64 (*nobits);
		// Tell S we are finished.
		*S = FINISH;
		// If S was PAD1, then set te first bit of M to one.
	if (*S == PAD1)
		M->e[0] =0x80;	
		// Keep the loop in sha256 for one more iteration.
	return 1;
	}


	// If we get down here, we haven't finished reading the file (S==READ).
	nobytes = fread(M->e, 1, 64, msgf);

	// Keep track of the number of bytes we've read.
	*nobits = *nobits + (nobytes * 8);
	// If we read less than 56 bytes, we can put all padding in tbis message block.
	if (nobytes < 56){
		// Add the one bit as per the standard.
		M->e[nobytes] = 0x80;
		// Add Zero bits until the last 64 bits
	while (nobytes < 56){
		nobytes = nobytes + 1;
		M->e[nobytes] = 0x00;
		}
		// Append the file size in bits as a (should be big endian) unsigned 64 bit int.
		M->s[7] = *nobits;
		// Tell S we are finished.
		*S = FINISH;
		// otherwise, check if we can put some padding into this message block.
	}else if (nobytes < 64){
		// Tell S we need another message block, with padding but with no one bit.
		*S = PAD0;
		// Put one bit into the current block.
		M->e[nobytes] = 0x80;
		// Pad the rest of the block with zero bits.
	while (nobytes < 64){	
		nobytes = nobytes + 1;
		M->e[nobytes] = 0x00;
		}
	// otherise check if we're just at the end of the file.
	}else if (feof(msgf)){
		// Tell S that we need another message block with all the padding.
		*S = PAD1;
		}
	// If we get this far, then return 1 so this function is called again.
	return 1;

	}
