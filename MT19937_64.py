
class MT19937_64(object):
    def __init__(self):
        self.mt = [0]*312
        self.mti = 313

    def seed(self, seed):
        self.mt[0] = seed & 0xffffffffffffffff
        for i in range(1, 312):
            self.mt[i] = (6364136223846793005 * (self.mt[i-1] ^ (self.mt[i-1] >> 62)) + i) & 0xffffffffffffffff
        self.mti = 312

    def int64(self):
        if self.mti >= 312:
            if self.mti == 313:
                self.seed(5489)

            for k in range(311):
                y = (self.mt[k] & 0xFFFFFFFF80000000) | (self.mt[k+1] & 0x7fffffff)
                if k < 312 - 156:
                    # self.mt[k] = self.mt[k+156] ^ (y >> 1) ^ (0xB5026F5AA96619E9 if y & 1 else 0)
                    self.mt[k] = self.mt[k + 156] ^ (y >> 1) ^ (0 if (y & 1) == 0 else 0xB5026F5AA96619E9)
                else:
                    # self.mt[k] = self.mt[k+156-624+len(self.mt)] ^ (y >> 1) ^ (0xB5026F5AA96619E9 if y & 1 else 0)
                    self.mt[k] = self.mt[k+156-624+len(self.mt)] ^ (y >> 1) ^ (0 if (y & 1) == 0 else 0xB5026F5AA96619E9)

            yy = (self.mt[311] & 0xFFFFFFFF80000000) | (self.mt[0] & 0x7fffffff)
            self.mt[311] = self.mt[155] ^ (yy >> 1) ^ (0 if (yy & 1) == 0 else 0xB5026F5AA96619E9)
            self.mti = 0

        x = self.mt[self.mti]
        self.mti += 1
        x ^= (x >> 29) & 0x5555555555555555
        x ^= (x << 17) & 0x71D67FFFEDA60000
        x ^= (x << 37) & 0xFFF7EEE000000000
        x ^= (x >> 43)

        return x


# if __name__ == '__main__':
#     first = MT19937_64()
#     first.seed(2534580088448263659)
#     gen = MT19937_64()
#     gen.seed(first.int64())
#     gen.int64()
#     key = b""
#     for j in range(0, 4096, 8):
#         num = gen.int64()
#         # print(num)
#         key += num.to_bytes(8, byteorder="big", signed=False)
#     print(key.hex())
