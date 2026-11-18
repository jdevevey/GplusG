from math import log, exp, pi

def entropy(P):
    #Returns the entropy of unnormalized proba mass function
    C = sum(P)
    return sum([-i*log(i,2) for i in P if i>0])/C + log(C, 2)

def trunc_gaussian(sigma, B):
    #Returns a table with unnormalized mass function for truncated gaussian
    return [exp(-i**2/(2*sigma**2)) for i in range(-int(B), int(B)+1)]

def high_bits(sigma, B, alpha):
    #high bits for hints are estimated to be HB(2z_2)
    B = int(B)
    bins = {}

    for z,w in zip(range(-B, B+1), trunc_gaussian(sigma, B)):
        h = (4*z + alpha) // (2*alpha) # HB(2*z)
        bins[h] = bins.get(h, 0.0) + w

    return list(bins.values())
