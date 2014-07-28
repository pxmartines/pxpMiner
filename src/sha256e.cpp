// SHA-256e. This code is Public Domain
#include <cstdint>
#include <cstring>

struct sha256e_state
{
    std::uint64_t length;
    std::uint32_t state[8];
    std::uint32_t curlen;
    unsigned char buf[64];
};

void sha256e_init(sha256e_state& md);
void sha256e_process(sha256e_state& md, const void* in, std::uint32_t inlen);
void sha256e_done(sha256e_state& md, void* out);



typedef std::uint32_t u32;
typedef std::uint64_t u64;

static const u32 K[64] =
{
	0xf8b08089UL, 0x047d6530UL, 0x00330006UL, 0x550c14e8UL, 
	0x34014bcfUL, 0x315d3869UL, 0x462020f4UL, 0x8bcd4484UL, 
	0xcbc78f3eUL, 0x2cd95846UL, 0xedf020acUL, 0xb66d9d6aUL, 
	0xaf5df2dcUL, 0x6b4351cdUL, 0xe615e66eUL, 0x6cdbc46eUL, 
	0x11933ccfUL, 0xda52c1dcUL, 0x8d85e923UL, 0x4db46ab1UL, 
	0xe0754960UL, 0xd3e0cdb5UL, 0xd38c7cb0UL, 0xd5ccdda7UL, 
	0xbafd8217UL, 0x229a2a7eUL, 0x3d84790eUL, 0xb0ca9ac4UL, 
	0xc503b675UL, 0x6743430bUL, 0x266f9c63UL, 0x6d6ec487UL, 
	0x75423a70UL, 0xdef486fdUL, 0xb1659be4UL, 0x83d75fb7UL, 
	0x7f2243ecUL, 0x05904224UL, 0x99200231UL, 0xa788360aUL, 
	0x082520acUL, 0xe30165f9UL, 0x9f8a6851UL, 0x07baa2efUL, 
	0x68558c65UL, 0x7228c639UL, 0xfc43f414UL, 0x123350dcUL, 
	0x249045a3UL, 0x79a58d63UL, 0xd22d6f01UL, 0x5f2731acUL, 
	0xf9516d1eUL, 0x75e5d048UL, 0xcee7fc1cUL, 0x4273e71aUL, 
	0xea7351b6UL, 0xf85076edUL, 0xb7e06dd1UL, 0x9fb2adddUL, 
	0xd502a8ebUL, 0xab269c7eUL, 0xf783f9caUL, 0x7aa6c820UL
};

static u32 min(u32 x, u32 y)
{
    return x < y ? x : y;
}

static u32 load32(const unsigned char* y)
{
    return (u32(y[0]) << 24) | (u32(y[1]) << 16) | (u32(y[2]) << 8) | (u32(y[3]) << 0);
}

static void store64(u64 x, unsigned char* y)
{
    for(int i = 0; i != 8; ++i)
        y[i] = (x >> ((7-i) * 8)) & 255;
}

static void store32(u32 x, unsigned char* y)
{
    for(int i = 0; i != 4; ++i)
        y[i] = (x >> ((3-i) * 8)) & 255;
}

static u32 Ch(u32 x, u32 y, u32 z)  { return z ^ (x & (y ^ z)); }
static u32 Maj(u32 x, u32 y, u32 z) { return ((x | y) & z) | (x & y); }
static u32 Rot(u32 x, u32 n)        { return (x >> (n & 31)) | (x << (32 - (n & 31))); }
static u32 Sh(u32 x, u32 n)         { return x >> n; }
static u32 Sigma0(u32 x)            { return Rot(x, 2) ^ Rot(x, 13) ^ Rot(x, 22); }
static u32 Sigma1(u32 x)            { return Rot(x, 6) ^ Rot(x, 11) ^ Rot(x, 25); }
static u32 Gamma0(u32 x)            { return Rot(x, 7) ^ Rot(x, 18) ^ Sh(x, 3); }
static u32 Gamma1(u32 x)            { return Rot(x, 17) ^ Rot(x, 19) ^ Sh(x, 10); }

static void sha256e_compress(sha256e_state& md, const unsigned char* buf)
{
    u32 S[8], W[64], t0, t1, t;

    // Copy state into S
    for(int i = 0; i < 8; i++)
        S[i] = md.state[i];

    // Copy the state into 512-bits into W[0..15]
    for(int i = 0; i < 16; i++)
        W[i] = load32(buf + (4*i));

    // Fill W[16..63]
    for(int i = 16; i < 64; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    // Compress
    auto RND = [&](u32 a, u32 b, u32 c, u32& d, u32 e, u32 f, u32 g, u32& h, u32 i)
    {
        t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        t1 = Sigma0(a) + Maj(a, b, c);
        d += t0;
        h  = t0 + t1;
    };

    for(int i = 0; i < 64; ++i)
    {
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
    }

    // Feedback
    for(int i = 0; i < 8; i++)
        md.state[i] = md.state[i] + S[i];
}

// Public interface

void sha256e_init(sha256e_state& md)
{
    md.curlen = 0;
    md.length = 0;
    md.state[0] = 0x6A09E667UL;
    md.state[1] = 0xBB67AE85UL;
    md.state[2] = 0x3C6EF372UL;
    md.state[3] = 0xA54FF53AUL;
    md.state[4] = 0x510E527FUL;
    md.state[5] = 0x9B05688CUL;
    md.state[6] = 0x1F83D9ABUL;
    md.state[7] = 0x5BE0CD19UL;
}

void sha256e_process(sha256e_state& md, const void* src, u32 inlen)
{
    const u32 block_size = sizeof(sha256e_state::buf);
    auto in = static_cast<const unsigned char*>(src);

    while(inlen > 0)
    {
        if(md.curlen == 0 && inlen >= block_size)
        {
            sha256e_compress(md, in);
            md.length += block_size * 8;
            in        += block_size;
            inlen     -= block_size;
        }
        else
        {
            u32 n = min(inlen, (block_size - md.curlen));
            std::memcpy(md.buf + md.curlen, in, n);
            md.curlen += n;
            in        += n;
            inlen     -= n;

            if(md.curlen == block_size)
            {
                sha256e_compress(md, md.buf);
                md.length += 8*block_size;
                md.curlen = 0;
            }
        }
    }
}

void sha256e_done(sha256e_state& md, void* out)
{
    // Increase the length of the message
    md.length += md.curlen * 8;

    // Append the '1' bit
    md.buf[md.curlen++] = static_cast<unsigned char>(0x80);

    // If the length is currently above 56 bytes we append zeros then compress.
    // Then we can fall back to padding zeros and length encoding like normal.
    if(md.curlen > 56)
    {
        while(md.curlen < 64)
            md.buf[md.curlen++] = 0;
        sha256e_compress(md, md.buf);
        md.curlen = 0;
    }

    // Pad upto 56 bytes of zeroes
    while(md.curlen < 56)
        md.buf[md.curlen++] = 0;

    // Store length
    store64(md.length, md.buf+56);
    sha256e_compress(md, md.buf);

    // Copy output
    for(int i = 0; i < 8; i++)
        store32(md.state[i], static_cast<unsigned char*>(out)+(4*i));
}

