
class Rand:
    def __init__(self):
        self.inext = 0
        self.inextp = 21
        self.MBIG = 2147483647  # maxint32
        self.MSEED = 161803398
        self.seed_array = [0] * 56

    def uin64(self):
        return int(self.sample() * 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF  # maxuint64

    def seed(self, seed):
        seed = seed & 0xFFFFFFFF
        if seed >> 31:
            seed = -((seed ^ 0xFFFFFFFF) + 1)  # uint转int
        if seed == -2147483648:  # minint32
            subtraction = 2147483647
        else:
            subtraction = seed
            if subtraction < 0:
                subtraction = -subtraction
        mj = self.MSEED - subtraction
        self.seed_array[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (i * 21) % 55
            self.seed_array[ii] = mk
            mk = mj - mk
            if mk < 0:
                mk += self.MBIG
            mj = self.seed_array[ii]
        for k in range(1, 5):
            for i in range(1, 56):
                self.seed_array[i] -= self.seed_array[1+(i+30) % 55]
                if self.seed_array[i] < 0:
                    self.seed_array[i] += self.MBIG
        self.inext = 0
        self.inextp = 21

    def sample(self):
        return float(self.internel_sample()) * (1/self.MBIG)

    def internel_sample(self):
        locINext = self.inext
        locINextp = self.inextp
        locINext += 1
        if locINext >= 56:
            locINext = 1
        locINextp += 1
        if locINextp >= 56:
            locINextp = 1
        ret_val = self.seed_array[locINext] - self.seed_array[locINextp]
        if ret_val == self.MBIG:
            ret_val -= 1
        if ret_val < 0:
            ret_val += self.MBIG
        self.seed_array[locINext] = ret_val
        self.inext = locINext
        self.inextp = locINextp
        return ret_val
