#include <metal_stdlib>
using namespace metal;

// Web版 crypt.wgsl の MSL 移植。bitslice DES ×32鍵並列。
// E-box の salt 適用は buffer(3) の定数テーブルで受け取る
// (Web版の #eNN テキスト置換と等価)。

struct CryptParams {
  uint baseLo;
  uint baseHi;
  uint count;
  uint _pad1;
};

constant uint kTblPC1[56] = {
  56,48,40,32,24,16,8,
  0,57,49,41,33,25,17,
  9,1,58,50,42,34,26,
  18,10,2,59,51,43,35,
  62,54,46,38,30,22,14,
  6,61,53,45,37,29,21,
  13,5,60,52,44,36,28,
  20,12,4,27,19,11,3
};

inline uint4 sbox1(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a4;
  uint x2 = ~a1;
  uint x3 = a4 ^ a3;
  uint x4 = x3 ^ x2;
  uint x5 = a3 | x2;
  uint x6 = x5 & x1;
  uint x7 = a6 | x6;
  uint x8 = x4 ^ x7;
  uint x9 = x1 | x2;
  uint x10 = a6 & x9;
  uint x11 = x7 ^ x10;
  uint x12 = a2 | x11;
  uint x13 = x8 ^ x12;
  uint x14 = x9 ^ x13;
  uint x15 = a6 | x14;
  uint x16 = x1 ^ x15;
  uint x17 = ~x14;
  uint x18 = x17 & x3;
  uint x19 = a2 | x18;
  uint x20 = x16 ^ x19;
  uint x21 = a5 | x20;
  uint x22 = x13 ^ x21;
  uint y4 = x22;
  uint x23 = a3 | x4;
  uint x24 = ~x23;
  uint x25 = a6 | x24;
  uint x26 = x6 ^ x25;
  uint x27 = x1 & x8;
  uint x28 = a2 | x27;
  uint x29 = x26 ^ x28;
  uint x30 = x1 | x8;
  uint x31 = x30 ^ x6;
  uint x32 = x5 & x14;
  uint x33 = x32 ^ x8;
  uint x34 = a2 & x33;
  uint x35 = x31 ^ x34;
  uint x36 = a5 | x35;
  uint x37 = x29 ^ x36;
  uint y1 = x37;
  uint x38 = a3 & x10;
  uint x39 = x38 | x4;
  uint x40 = a3 & x33;
  uint x41 = x40 ^ x25;
  uint x42 = a2 | x41;
  uint x43 = x39 ^ x42;
  uint x44 = a3 | x26;
  uint x45 = x44 ^ x14;
  uint x46 = a1 | x8;
  uint x47 = x46 ^ x20;
  uint x48 = a2 | x47;
  uint x49 = x45 ^ x48;
  uint x50 = a5 & x49;
  uint x51 = x43 ^ x50;
  uint y2 = x51;
  uint x52 = x8 ^ x40;
  uint x53 = a3 ^ x11;
  uint x54 = x53 & x5;
  uint x55 = a2 | x54;
  uint x56 = x52 ^ x55;
  uint x57 = a6 | x4;
  uint x58 = x57 ^ x38;
  uint x59 = x13 & x56;
  uint x60 = a2 & x59;
  uint x61 = x58 ^ x60;
  uint x62 = a5 & x61;
  uint x63 = x56 ^ x62;
  uint y3 = x63;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox2(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a5;
  uint x2 = ~a1;
  uint x3 = a5 ^ a6;
  uint x4 = x3 ^ x2;
  uint x5 = x4 ^ a2;
  uint x6 = a6 | x1;
  uint x7 = x6 | x2;
  uint x8 = a2 & x7;
  uint x9 = a6 ^ x8;
  uint x10 = a3 & x9;
  uint x11 = x5 ^ x10;
  uint x12 = a2 & x9;
  uint x13 = a5 ^ x6;
  uint x14 = a3 | x13;
  uint x15 = x12 ^ x14;
  uint x16 = a4 & x15;
  uint x17 = x11 ^ x16;
  uint y2 = x17;
  uint x18 = a5 | a1;
  uint x19 = a6 | x18;
  uint x20 = x13 ^ x19;
  uint x21 = x20 ^ a2;
  uint x22 = a6 | x4;
  uint x23 = x22 & x17;
  uint x24 = a3 | x23;
  uint x25 = x21 ^ x24;
  uint x26 = a6 | x2;
  uint x27 = a5 & x2;
  uint x28 = a2 | x27;
  uint x29 = x26 ^ x28;
  uint x30 = x3 ^ x27;
  uint x31 = x2 ^ x19;
  uint x32 = a2 & x31;
  uint x33 = x30 ^ x32;
  uint x34 = a3 & x33;
  uint x35 = x29 ^ x34;
  uint x36 = a4 | x35;
  uint x37 = x25 ^ x36;
  uint y3 = x37;
  uint x38 = x21 & x32;
  uint x39 = x38 ^ x5;
  uint x40 = a1 | x15;
  uint x41 = x40 ^ x13;
  uint x42 = a3 | x41;
  uint x43 = x39 ^ x42;
  uint x44 = x28 | x41;
  uint x45 = a4 & x44;
  uint x46 = x43 ^ x45;
  uint y1 = x46;
  uint x47 = x19 & x21;
  uint x48 = x47 ^ x26;
  uint x49 = a2 & x33;
  uint x50 = x49 ^ x21;
  uint x51 = a3 & x50;
  uint x52 = x48 ^ x51;
  uint x53 = x18 & x28;
  uint x54 = x53 & x50;
  uint x55 = a4 | x54;
  uint x56 = x52 ^ x55;
  uint y4 = x56;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox3(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a5;
  uint x2 = ~a6;
  uint x3 = a5 & a3;
  uint x4 = x3 ^ a6;
  uint x5 = a4 & x1;
  uint x6 = x4 ^ x5;
  uint x7 = x6 ^ a2;
  uint x8 = a3 & x1;
  uint x9 = a5 ^ x2;
  uint x10 = a4 | x9;
  uint x11 = x8 ^ x10;
  uint x12 = x7 & x11;
  uint x13 = a5 ^ x11;
  uint x14 = x13 | x7;
  uint x15 = a4 & x14;
  uint x16 = x12 ^ x15;
  uint x17 = a2 & x16;
  uint x18 = x11 ^ x17;
  uint x19 = a1 & x18;
  uint x20 = x7 ^ x19;
  uint y4 = x20;
  uint x21 = a3 ^ a4;
  uint x22 = x21 ^ x9;
  uint x23 = x2 | x4;
  uint x24 = x23 ^ x8;
  uint x25 = a2 | x24;
  uint x26 = x22 ^ x25;
  uint x27 = a6 ^ x23;
  uint x28 = x27 | a4;
  uint x29 = a3 ^ x15;
  uint x30 = x29 | x5;
  uint x31 = a2 | x30;
  uint x32 = x28 ^ x31;
  uint x33 = a1 | x32;
  uint x34 = x26 ^ x33;
  uint y1 = x34;
  uint x35 = a3 ^ x9;
  uint x36 = x35 | x5;
  uint x37 = x4 | x29;
  uint x38 = x37 ^ a4;
  uint x39 = a2 | x38;
  uint x40 = x36 ^ x39;
  uint x41 = a6 & x11;
  uint x42 = x41 | x6;
  uint x43 = x34 ^ x38;
  uint x44 = x43 ^ x41;
  uint x45 = a2 & x44;
  uint x46 = x42 ^ x45;
  uint x47 = a1 | x46;
  uint x48 = x40 ^ x47;
  uint y3 = x48;
  uint x49 = x2 | x38;
  uint x50 = x49 ^ x13;
  uint x51 = x27 ^ x28;
  uint x52 = a2 | x51;
  uint x53 = x50 ^ x52;
  uint x54 = x12 & x23;
  uint x55 = x54 & x52;
  uint x56 = a1 | x55;
  uint x57 = x53 ^ x56;
  uint y2 = x57;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox4(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a1;
  uint x2 = ~a3;
  uint x3 = a1 | a3;
  uint x4 = a5 & x3;
  uint x5 = x1 ^ x4;
  uint x6 = a2 | a3;
  uint x7 = x5 ^ x6;
  uint x8 = a1 & a5;
  uint x9 = x8 ^ x3;
  uint x10 = a2 & x9;
  uint x11 = a5 ^ x10;
  uint x12 = a4 & x11;
  uint x13 = x7 ^ x12;
  uint x14 = x2 ^ x4;
  uint x15 = a2 & x14;
  uint x16 = x9 ^ x15;
  uint x17 = x5 & x14;
  uint x18 = a5 ^ x2;
  uint x19 = a2 | x18;
  uint x20 = x17 ^ x19;
  uint x21 = a4 | x20;
  uint x22 = x16 ^ x21;
  uint x23 = a6 & x22;
  uint x24 = x13 ^ x23;
  uint y2 = x24;
  uint x25 = ~x13;
  uint x26 = a6 | x22;
  uint x27 = x25 ^ x26;
  uint y1 = x27;
  uint x28 = a2 & x11;
  uint x29 = x28 ^ x17;
  uint x30 = a3 ^ x10;
  uint x31 = x30 ^ x19;
  uint x32 = a4 & x31;
  uint x33 = x29 ^ x32;
  uint x34 = x25 ^ x33;
  uint x35 = a2 & x34;
  uint x36 = x24 ^ x35;
  uint x37 = a4 | x34;
  uint x38 = x36 ^ x37;
  uint x39 = a6 & x38;
  uint x40 = x33 ^ x39;
  uint y4 = x40;
  uint x41 = x26 ^ x38;
  uint x42 = x41 ^ x40;
  uint y3 = x42;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox5(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a6;
  uint x2 = ~a3;
  uint x3 = x1 | x2;
  uint x4 = x3 ^ a4;
  uint x5 = a1 & x3;
  uint x6 = x4 ^ x5;
  uint x7 = a6 | a4;
  uint x8 = x7 ^ a3;
  uint x9 = a3 | x7;
  uint x10 = a1 | x9;
  uint x11 = x8 ^ x10;
  uint x12 = a5 & x11;
  uint x13 = x6 ^ x12;
  uint x14 = ~x4;
  uint x15 = x14 & a6;
  uint x16 = a1 | x15;
  uint x17 = x8 ^ x16;
  uint x18 = a5 | x17;
  uint x19 = x10 ^ x18;
  uint x20 = a2 | x19;
  uint x21 = x13 ^ x20;
  uint y3 = x21;
  uint x22 = x2 | x15;
  uint x23 = x22 ^ a6;
  uint x24 = a4 ^ x22;
  uint x25 = a1 & x24;
  uint x26 = x23 ^ x25;
  uint x27 = a1 ^ x11;
  uint x28 = x27 & x22;
  uint x29 = a5 | x28;
  uint x30 = x26 ^ x29;
  uint x31 = a4 | x27;
  uint x32 = ~x31;
  uint x33 = a2 | x32;
  uint x34 = x30 ^ x33;
  uint y2 = x34;
  uint x35 = x2 ^ x15;
  uint x36 = a1 & x35;
  uint x37 = x14 ^ x36;
  uint x38 = x5 ^ x7;
  uint x39 = x38 & x34;
  uint x40 = a5 | x39;
  uint x41 = x37 ^ x40;
  uint x42 = x2 ^ x5;
  uint x43 = x42 & x16;
  uint x44 = x4 & x27;
  uint x45 = a5 & x44;
  uint x46 = x43 ^ x45;
  uint x47 = a2 | x46;
  uint x48 = x41 ^ x47;
  uint y1 = x48;
  uint x49 = x24 & x48;
  uint x50 = x49 ^ x5;
  uint x51 = x11 ^ x30;
  uint x52 = x51 | x50;
  uint x53 = a5 & x52;
  uint x54 = x50 ^ x53;
  uint x55 = x14 ^ x19;
  uint x56 = x55 ^ x34;
  uint x57 = x4 ^ x16;
  uint x58 = x57 & x30;
  uint x59 = a5 & x58;
  uint x60 = x56 ^ x59;
  uint x61 = a2 | x60;
  uint x62 = x54 ^ x61;
  uint y4 = x62;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox6(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a2;
  uint x2 = ~a5;
  uint x3 = a2 ^ a6;
  uint x4 = x3 ^ x2;
  uint x5 = x4 ^ a1;
  uint x6 = a5 & a6;
  uint x7 = x6 | x1;
  uint x8 = a5 & x5;
  uint x9 = a1 & x8;
  uint x10 = x7 ^ x9;
  uint x11 = a4 & x10;
  uint x12 = x5 ^ x11;
  uint x13 = a6 ^ x10;
  uint x14 = x13 & a1;
  uint x15 = a2 & a6;
  uint x16 = x15 ^ a5;
  uint x17 = a1 & x16;
  uint x18 = x2 ^ x17;
  uint x19 = a4 | x18;
  uint x20 = x14 ^ x19;
  uint x21 = a3 & x20;
  uint x22 = x12 ^ x21;
  uint y2 = x22;
  uint x23 = a6 ^ x18;
  uint x24 = a1 & x23;
  uint x25 = a5 ^ x24;
  uint x26 = a2 ^ x17;
  uint x27 = x26 | x6;
  uint x28 = a4 & x27;
  uint x29 = x25 ^ x28;
  uint x30 = ~x26;
  uint x31 = a6 | x29;
  uint x32 = ~x31;
  uint x33 = a4 & x32;
  uint x34 = x30 ^ x33;
  uint x35 = a3 & x34;
  uint x36 = x29 ^ x35;
  uint y4 = x36;
  uint x37 = x6 ^ x34;
  uint x38 = a5 & x23;
  uint x39 = x38 ^ x5;
  uint x40 = a4 | x39;
  uint x41 = x37 ^ x40;
  uint x42 = x16 | x24;
  uint x43 = x42 ^ x1;
  uint x44 = x15 ^ x24;
  uint x45 = x44 ^ x31;
  uint x46 = a4 | x45;
  uint x47 = x43 ^ x46;
  uint x48 = a3 | x47;
  uint x49 = x41 ^ x48;
  uint y1 = x49;
  uint x50 = x5 | x38;
  uint x51 = x50 ^ x6;
  uint x52 = x8 & x31;
  uint x53 = a4 | x52;
  uint x54 = x51 ^ x53;
  uint x55 = x30 & x43;
  uint x56 = a3 | x55;
  uint x57 = x54 ^ x56;
  uint y3 = x57;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox7(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a2;
  uint x2 = ~a5;
  uint x3 = a2 & a4;
  uint x4 = x3 ^ a5;
  uint x5 = x4 ^ a3;
  uint x6 = a4 & x4;
  uint x7 = x6 ^ a2;
  uint x8 = a3 & x7;
  uint x9 = a1 ^ x8;
  uint x10 = a6 | x9;
  uint x11 = x5 ^ x10;
  uint x12 = a4 & x2;
  uint x13 = x12 | a2;
  uint x14 = a2 | x2;
  uint x15 = a3 & x14;
  uint x16 = x13 ^ x15;
  uint x17 = x6 ^ x11;
  uint x18 = a6 | x17;
  uint x19 = x16 ^ x18;
  uint x20 = a1 & x19;
  uint x21 = x11 ^ x20;
  uint y1 = x21;
  uint x22 = a2 | x21;
  uint x23 = x22 ^ x6;
  uint x24 = x23 ^ x15;
  uint x25 = x5 ^ x6;
  uint x26 = x25 | x12;
  uint x27 = a6 | x26;
  uint x28 = x24 ^ x27;
  uint x29 = x1 & x19;
  uint x30 = x23 & x26;
  uint x31 = a6 & x30;
  uint x32 = x29 ^ x31;
  uint x33 = a1 | x32;
  uint x34 = x28 ^ x33;
  uint y4 = x34;
  uint x35 = a4 & x16;
  uint x36 = x35 | x1;
  uint x37 = a6 & x36;
  uint x38 = x11 ^ x37;
  uint x39 = a4 & x13;
  uint x40 = a3 | x7;
  uint x41 = x39 ^ x40;
  uint x42 = x1 | x24;
  uint x43 = a6 | x42;
  uint x44 = x41 ^ x43;
  uint x45 = a1 | x44;
  uint x46 = x38 ^ x45;
  uint y2 = x46;
  uint x47 = x8 ^ x44;
  uint x48 = x6 ^ x15;
  uint x49 = a6 | x48;
  uint x50 = x47 ^ x49;
  uint x51 = x19 ^ x44;
  uint x52 = a4 ^ x25;
  uint x53 = x52 & x46;
  uint x54 = a6 & x53;
  uint x55 = x51 ^ x54;
  uint x56 = a1 | x55;
  uint x57 = x50 ^ x56;
  uint y3 = x57;
  return uint4(y1, y2, y3, y4);
}

inline uint4 sbox8(uint a1, uint a2, uint a3, uint a4, uint a5, uint a6) {
  uint x1 = ~a1;
  uint x2 = ~a4;
  uint x3 = a3 ^ x1;
  uint x4 = a3 | x1;
  uint x5 = x4 ^ x2;
  uint x6 = a5 | x5;
  uint x7 = x3 ^ x6;
  uint x8 = x1 | x5;
  uint x9 = x2 ^ x8;
  uint x10 = a5 & x9;
  uint x11 = x8 ^ x10;
  uint x12 = a2 & x11;
  uint x13 = x7 ^ x12;
  uint x14 = x6 ^ x9;
  uint x15 = x3 & x9;
  uint x16 = a5 & x8;
  uint x17 = x15 ^ x16;
  uint x18 = a2 | x17;
  uint x19 = x14 ^ x18;
  uint x20 = a6 | x19;
  uint x21 = x13 ^ x20;
  uint y1 = x21;
  uint x22 = a5 | x3;
  uint x23 = x22 & x2;
  uint x24 = ~a3;
  uint x25 = x24 & x8;
  uint x26 = a5 & x4;
  uint x27 = x25 ^ x26;
  uint x28 = a2 | x27;
  uint x29 = x23 ^ x28;
  uint x30 = a6 & x29;
  uint x31 = x13 ^ x30;
  uint y4 = x31;
  uint x32 = x5 ^ x6;
  uint x33 = x32 ^ x22;
  uint x34 = a4 | x13;
  uint x35 = a2 & x34;
  uint x36 = x33 ^ x35;
  uint x37 = a1 & x33;
  uint x38 = x37 ^ x8;
  uint x39 = a1 ^ x23;
  uint x40 = x39 & x7;
  uint x41 = a2 & x40;
  uint x42 = x38 ^ x41;
  uint x43 = a6 | x42;
  uint x44 = x36 ^ x43;
  uint y3 = x44;
  uint x45 = a1 ^ x10;
  uint x46 = x45 ^ x22;
  uint x47 = ~x7;
  uint x48 = x47 & x8;
  uint x49 = a2 | x48;
  uint x50 = x46 ^ x49;
  uint x51 = x19 ^ x29;
  uint x52 = x51 | x38;
  uint x53 = a6 & x52;
  uint x54 = x50 ^ x53;
  uint y2 = x54;
  return uint4(y1, y2, y3, y4);
}

inline void des_round(thread uint *lr, thread uint *k, constant uint *ebox, thread uint *o) {
  uint er0  = lr[ebox[0]] ^ k[0];
  uint er1  = lr[ebox[1]] ^ k[1];
  uint er2  = lr[ebox[2]] ^ k[2];
  uint er3  = lr[ebox[3]] ^ k[3];
  uint er4  = lr[ebox[4]] ^ k[4];
  uint er5  = lr[ebox[5]] ^ k[5];
  uint4 s1 = sbox1(er0, er1, er2, er3, er4, er5);
  o[8]   = lr[40]; o[40] = lr[8]   ^ s1.x;
  o[16]  = lr[48]; o[48] = lr[16]  ^ s1.y;
  o[22]  = lr[54]; o[54] = lr[22]  ^ s1.z;
  o[30]  = lr[62]; o[62] = lr[30]  ^ s1.w;

  uint er6  = lr[ebox[6]] ^ k[6];
  uint er7  = lr[ebox[7]] ^ k[7];
  uint er8  = lr[ebox[8]] ^ k[8];
  uint er9  = lr[ebox[9]] ^ k[9];
  uint er10 = lr[ebox[10]] ^ k[10];
  uint er11 = lr[ebox[11]] ^ k[11];
  uint4 s2 = sbox2(er6, er7, er8, er9, er10, er11);
  o[12]  = lr[44]; o[44] = lr[12]  ^ s2.x;
  o[27]  = lr[59]; o[59] = lr[27]  ^ s2.y;
  o[1]   = lr[33]; o[33] = lr[1]   ^ s2.z;
  o[17]  = lr[49]; o[49] = lr[17]  ^ s2.w;

  uint er12 = lr[ebox[12]] ^ k[12];
  uint er13 = lr[ebox[13]] ^ k[13];
  uint er14 = lr[ebox[14]] ^ k[14];
  uint er15 = lr[ebox[15]] ^ k[15];
  uint er16 = lr[ebox[16]] ^ k[16];
  uint er17 = lr[ebox[17]] ^ k[17];
  uint4 s3 = sbox3(er12, er13, er14, er15, er16, er17);
  o[23]  = lr[55]; o[55] = lr[23]  ^ s3.x;
  o[15]  = lr[47]; o[47] = lr[15]  ^ s3.y;
  o[29]  = lr[61]; o[61] = lr[29]  ^ s3.z;
  o[5]   = lr[37]; o[37] = lr[5]   ^ s3.w;

  uint er18 = lr[ebox[18]] ^ k[18];
  uint er19 = lr[ebox[19]] ^ k[19];
  uint er20 = lr[ebox[20]] ^ k[20];
  uint er21 = lr[ebox[21]] ^ k[21];
  uint er22 = lr[ebox[22]] ^ k[22];
  uint er23 = lr[ebox[23]] ^ k[23];
  uint4 s4 = sbox4(er18, er19, er20, er21, er22, er23);
  o[25]  = lr[57]; o[57] = lr[25]  ^ s4.x;
  o[19]  = lr[51]; o[51] = lr[19]  ^ s4.y;
  o[9]   = lr[41]; o[41] = lr[9]   ^ s4.z;
  o[0]   = lr[32]; o[32] = lr[0]   ^ s4.w;

  uint er24 = lr[ebox[24]] ^ k[24];
  uint er25 = lr[ebox[25]] ^ k[25];
  uint er26 = lr[ebox[26]] ^ k[26];
  uint er27 = lr[ebox[27]] ^ k[27];
  uint er28 = lr[ebox[28]] ^ k[28];
  uint er29 = lr[ebox[29]] ^ k[29];
  uint4 s5 = sbox5(er24, er25, er26, er27, er28, er29);
  o[7]   = lr[39]; o[39] = lr[7]   ^ s5.x;
  o[13]  = lr[45]; o[45] = lr[13]  ^ s5.y;
  o[24]  = lr[56]; o[56] = lr[24]  ^ s5.z;
  o[2]   = lr[34]; o[34] = lr[2]   ^ s5.w;

  uint er30 = lr[ebox[30]] ^ k[30];
  uint er31 = lr[ebox[31]] ^ k[31];
  uint er32 = lr[ebox[32]] ^ k[32];
  uint er33 = lr[ebox[33]] ^ k[33];
  uint er34 = lr[ebox[34]] ^ k[34];
  uint er35 = lr[ebox[35]] ^ k[35];
  uint4 s6 = sbox6(er30, er31, er32, er33, er34, er35);
  o[3]   = lr[35]; o[35] = lr[3]   ^ s6.x;
  o[28]  = lr[60]; o[60] = lr[28]  ^ s6.y;
  o[10]  = lr[42]; o[42] = lr[10]  ^ s6.z;
  o[18]  = lr[50]; o[50] = lr[18]  ^ s6.w;

  uint er36 = lr[ebox[36]] ^ k[36];
  uint er37 = lr[ebox[37]] ^ k[37];
  uint er38 = lr[ebox[38]] ^ k[38];
  uint er39 = lr[ebox[39]] ^ k[39];
  uint er40 = lr[ebox[40]] ^ k[40];
  uint er41 = lr[ebox[41]] ^ k[41];
  uint4 s7 = sbox7(er36, er37, er38, er39, er40, er41);
  o[31]  = lr[63]; o[63] = lr[31]  ^ s7.x;
  o[11]  = lr[43]; o[43] = lr[11]  ^ s7.y;
  o[21]  = lr[53]; o[53] = lr[21]  ^ s7.z;
  o[6]   = lr[38]; o[38] = lr[6]   ^ s7.w;

  uint er42 = lr[ebox[42]] ^ k[42];
  uint er43 = lr[ebox[43]] ^ k[43];
  uint er44 = lr[ebox[44]] ^ k[44];
  uint er45 = lr[ebox[45]] ^ k[45];
  uint er46 = lr[ebox[46]] ^ k[46];
  uint er47 = lr[ebox[47]] ^ k[47];
  uint4 s8 = sbox8(er42, er43, er44, er45, er46, er47);
  o[4]   = lr[36]; o[36] = lr[4]   ^ s8.x;
  o[26]  = lr[58]; o[58] = lr[26]  ^ s8.y;
  o[14]  = lr[46]; o[46] = lr[14]  ^ s8.z;
  o[20]  = lr[52]; o[52] = lr[20]  ^ s8.w;
}

inline void key_schedule_pc1(thread uint *key, thread uint *CD) {
  for (uint i = 0; i < 56; i++) {
    CD[i] = key[kTblPC1[i] + 1u];
  }
}

inline void key_schedule_pc2(thread uint *CD, constant uint *table, uint r, thread uint *subkey) {
  for (uint i = 0; i < 12; i++) {
    uint4 v = uint4(table[r * 48u + i * 4u], table[r * 48u + i * 4u + 1u],
                    table[r * 48u + i * 4u + 2u], table[r * 48u + i * 4u + 3u]);
    subkey[i * 4u] = CD[v.x];
    subkey[i * 4u + 1u] = CD[v.y];
    subkey[i * 4u + 2u] = CD[v.z];
    subkey[i * 4u + 3u] = CD[v.w];
  }
}

inline void des_16rounds(thread uint *lr_in, thread uint *CD,
                         constant uint *pc2, constant uint *ebox, thread uint *o) {
  uint subkey[48];
  uint lr[64];
  uint tmp[64];
  for (uint i = 0; i < 64; i++) { lr[i] = lr_in[i]; }
  key_schedule_pc2(CD, pc2, 0, subkey);
  des_round(lr, subkey, ebox, tmp);
  for (uint i = 0; i < 64; i++) { lr[i] = tmp[i]; }
  for (uint r = 1; r < 16; r++) {
    key_schedule_pc2(CD, pc2, r, subkey);
    des_round(lr, subkey, ebox, tmp);
    for (uint i = 0; i < 64; i++) { lr[i] = tmp[i]; }
  }
  for (uint i = 0; i < 32; i++) {
    o[i] = lr[i + 32];
    o[i + 32] = lr[i];
  }
}

inline uint2 add64u(uint lo, uint hi, uint add) {
  uint nlo = lo + add;
  uint carry = (nlo < lo) ? 1u : 0u;
  return uint2(nlo, hi + carry);
}

inline void make_block(uint baseLo, uint baseHi, uint gid, thread uint *o) {
  for (uint i = 0; i < 64; i++) { o[i] = 0u; }
  uint step = 7u;
  uint start = gid * 32u * step;
  for (uint lane = 0; lane < 32; lane++) {
    uint2 key = add64u(baseLo, baseHi, start + lane * step);
    uint lo = key.x;
    uint hi = key.y;
    uint mask = 1u << lane;
    for (uint b = 0; b < 32; b++) {
      uint bit = (hi >> (31u - b)) & 1u;
      if (bit != 0u) { o[b] |= mask; }
    }
    for (uint b = 0; b < 32; b++) {
      uint bit = (lo >> (31u - b)) & 1u;
      if (bit != 0u) { o[b + 32u] |= mask; }
    }
  }
}

#regex_matcher_code

kernel void main(uint gid [[thread_position_in_grid]],
                 constant CryptParams &params [[buffer(0)]],
                 device uint *output [[buffer(1)]],
                 constant uint *pc2table [[buffer(2)]],
                 constant uint *ebox [[buffer(3)]]) {
  if (gid >= params.count) {
    return;
  }
  uint lr[64];
  make_block(params.baseLo, params.baseHi, gid, lr);

  uint CD[56];
  // key[] は1-indexed相当: key[0]未使用、lr[i]→key[i+1]
  uint key[65];
  key[0] = 0u;
  for (uint i = 0; i < 64; i++) { key[i + 1u] = lr[i]; }
  key_schedule_pc1(key, CD);

  uint state[64];
  uint tmp[64];
  for (uint i = 0; i < 64; i++) { state[i] = 0u; }
  for (uint i = 0; i < 25; i++) {
    des_16rounds(state, CD, pc2table, ebox, tmp);
    for (uint j = 0; j < 64; j++) { state[j] = tmp[j]; }
  }

  // FPの並び替えは生成matcher側で吸収する
  output[gid] = regex_match(state);
}
