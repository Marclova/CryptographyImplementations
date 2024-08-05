#include <stdio.h>
#include <Cyclone\cycloneCrypto\pkc\dsa.h>
#include <Cyclone\cycloneCrypto\ecc\ecdsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>

#define SEED_LENGTH 32 // Length in bytes for SHA-256 seed

int main(int argc, char const *argv[])
{
    printf("\n");

    // Mpi n;
    // mpiInit(&n);
    // mpiSetValue(&n, 62500);
    
    // Mpi appendV;
    // mpiInit(&appendV);
    // Mpi v;
    // mpiInit(&v);
    // mpiSetValue(&v, 1);
    // Mpi previousV;
    // mpiInit(&previousV);
    // mpiSetValue(&previousV, 0);

    // while (mpiComp(&v, &previousV) != 0)
    // {
    //     //set previous value
    //     mpiCopy(&previousV, &v);
    //     //calculate v = (v + n / v) / 2
    //     //appendValue = n / v
    //     mpiDiv(&appendV, (Mpi *)NULL, &n, &v);
    //     //v = v + appendValue
    //     mpiAdd(&v, &v, &appendV);
    //     // v /= 2
    //     mpiDivInt(&v, (Mpi *)NULL, &v, 2);
    // }

    // mpiFree(&appendV);
    // mpiFree(&v);
    // mpiFree(&previousV);

    
    // Mpi p;
    // mpiInit(&p);
    // mpiSetValue(&p, 103042);
    // Mpi r;
    // mpiInit(&r);

    // mpiSquareRoot(&r, &p);
    
    // printf("v: %s%u\n", (r.sign == 1) ? "" : "-", r.data[0]);

    Mpi gX;
    mpiInit(&gX);
    mpiSetValue(&gX, 16);
    Mpi r;
    mpiInit(&r);
    EcPoint point;
    ecInit(&point);
    
    EcDomainParameters params;
    ecInitDomainParameters(&params);
    mpiSetValue(&params.a, 7);
    mpiSetValue(&params.b, 17);
    mpiSetValue(&params.p, 107);
    ecGenerateCurvePoint(&params, &gX, &params.g);
    ecCopy(&point, &params.g);

    // ecDouble(&params, &params.g, &params.g);

    // while (mpiCompInt(&params.g.z, 0) == 1)
    // {
    //     ecAdd(&params, &params.g, &params.g, &point);
    // }

    mpiSetValue(&point.x, 62);
    mpiSetValue(&point.y, 93);
    mpiSetValue(&point.z, 77);
    
    ecCalculatePointOrder(&params, &point, &r);

    printf("point order: %s%u", (point.z.sign == 1) ? "" : "-", r.data[0]);

    // printf("point retrieved!\n X:%u   Y:%u   z:%s%u\n", params.g.x.data[0], params.g.y.data[0],
    //                                                     (params.g.z.sign == 1) ? "" : "-", params.g.z.data[0]);
    
    // for (size_t i = 1; i < 107; i++)
    // {
    //     mpiSetValue(&gX, i);
    //     ecGenerateCurvePoint(&params, &gX, &params.g);
    //     printf("X: %u   Y: %d\n", i, (params.g.y.sign == 1) ? &params.g.y.data[0] : -1);
    // }

    printf("\n\n");
    for (size_t i = 1; i < 107; i++)
    {
        mpiSetValue(&gX, i);
        ecGenerateCurvePoint(&params, &gX, &point);
        printf("X: %u   Y:%d\n", i, (point.y.data == NULL) ? -1 : point.y.data[0]);
    }
    
    

    //TODO test ecCalculatePointGrade
}
