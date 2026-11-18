#q = 114689 & 59393
#Look for 2n-th primitive roots of unit
def find_root(q, n):
    for i in range(1,q):
        if pow(i, n, q)!=1 and pow(i, 2*n, q)==1:
            return i


def bitrev(k, log_n):
    #reverses bits of k < 2**log_n
    return sum([((k>>i)%2)*2**(log_n-i-1) for i in range(log_n)])


#log_2(512) = 9, log_2(1024) = 10
print(find_root(114689, 512))
print(find_root(86017, 1024))

zeta = find_root(114689, 512)
print("T_zeta_list = [",[114689] + [pow(zeta, bitrev(i, 9), 114689) for i in range(1, 512)], ",")
zeta = find_root(86017, 1024)
print([86017] + [pow(zeta, bitrev(i, 10), 86017) for i in range(1, 1024)], "]")
