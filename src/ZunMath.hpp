#pragma once

#include "GameWindow.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <GL/gl.h>
#include <cmath>
#include <cstring>

#define glDepthRangef glDepthRange
#define glFrustumf glFrustum

// sizeof checks kept in because technically, the standard does allow compilers to add more padding than is required

// Replacing all former uses of D3DXVECTOR2
struct ZunVec2
{
    f32 x;
    f32 y;

    ZunVec2()
    {
    }

    ZunVec2(f32 x, f32 y)
    {
        this->x = x;
        this->y = y;
    }

    f32 VectorLength()
    {
        return sqrt(this->x * this->x + this->y * this->y);
    }

    f64 VectorLengthF64()
    {
        return (f64)this->VectorLength();
    }
};
static_assert(sizeof(ZunVec2) == 0x08, "ZunVec2 has additional padding between struct members!");

// Replacing all former uses of D3DXVECTOR3
struct ZunVec3
{
    f32 x;
    f32 y;
    f32 z;

    ZunVec3()
    {
    }

    ZunVec3(f32 x, f32 y, f32 z)
    {
        this->x = x;
        this->y = y;
        this->z = z;
    }

    ZunVec3 operator-() const
    {
        return ZunVec3(-this->x, -this->y, -this->z);
    }

    ZunVec3 operator+(const ZunVec3 &b) const
    {
        return ZunVec3(this->x + b.x, this->y + b.y, this->z + b.z);
    }

    ZunVec3 &operator+=(const ZunVec3 &b)
    {
        this->x += b.x;
        this->y += b.y;
        this->z += b.z;

        return *this;
    }

    ZunVec3 operator-(const ZunVec3 &b) const
    {
        return ZunVec3(this->x - b.x, this->y - b.y, this->z - b.z);
    }

    ZunVec3 &operator-=(const ZunVec3 &b)
    {
        this->x -= b.x;
        this->y -= b.y;
        this->z -= b.z;

        return *this;
    }

    ZunVec3 operator*(const f32 mult) const
    {
        return ZunVec3(this->x * mult, this->y * mult, this->z * mult);
    }

    ZunVec3 &operator*=(const f32 mult)
    {
        this->x *= mult;
        this->y *= mult;
        this->z *= mult;

        return *this;
    }

    ZunVec3 operator/(const f32 divisor) const
    {
        return ZunVec3(this->x / divisor, this->y / divisor, this->z / divisor);
    }

    ZunVec3 &operator/=(const f32 div)
    {
        this->x /= div;
        this->y /= div;
        this->z /= div;

        return *this;
    }

    f32 getMagnitude()
    {
        return std::sqrtf(this->x * this->x + this->y * this->y + this->z * this->z);
    }

    void getNormalized(ZunVec3 &norm)
    {
        norm = *this / this->getMagnitude();
    }

    void calcCross(ZunVec3 &dst, ZunVec3 &vec)
    {
        dst = ZunVec3(this->y * vec.z - this->z * vec.y, this->z * vec.x - this->x * vec.z,
                      this->x * vec.y - this->y * vec.x);
    }

    f32 calcDot(ZunVec3 &vec)
    {
        return this->x * vec.x + this->y * vec.y + this->z * vec.z;
    }

    static void SetVecCorners(ZunVec3 *topLeftCorner, ZunVec3 *bottomRightCorner, const ZunVec3 *centerPosition,
                              const ZunVec3 *size)
    {
        topLeftCorner->x = centerPosition->x - size->x / 2.0f;
        topLeftCorner->y = centerPosition->y - size->y / 2.0f;
        bottomRightCorner->x = size->x / 2.0f + centerPosition->x;
        bottomRightCorner->y = size->y / 2.0f + centerPosition->y;
    }
};
static_assert(sizeof(ZunVec3) == 0x0C, "ZunVec3 has additional padding between struct members!");

struct ZunVec4
{
    f32 x;
    f32 y;
    f32 z;
    f32 w;

    ZunVec4()
    {
    }

    ZunVec4(f32 x, f32 y, f32 z, f32 w)
    {
        this->x = x;
        this->y = y;
        this->z = z;
        this->w = w;
    }
};
static_assert(sizeof(ZunVec4) == 0x10, "ZunVec4 has additional padding between struct members!");

// Replacing all former uses of D3DXMATRIX
struct ZunMatrix
{
    f32 m[4][4];

    ZunMatrix operator*(const ZunMatrix &b) const
    {
        ZunMatrix result;

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                result.m[i][j] = 0.0f;

                for (int k = 0; k < 4; k++)
                {
                    result.m[i][j] += this->m[k][j] * b.m[i][k];
                }
            }
        }

        return result;
    }

    ZunVec3 operator*(const ZunVec3 &b) const
    {
        ZunVec3 result(0.0f, 0.0f, 0.0f);

        result.x = this->m[0][0] * b.x + this->m[1][0] * b.y + this->m[2][0] * b.z + this->m[3][0];
        result.y = this->m[0][1] * b.x + this->m[1][1] * b.y + this->m[2][1] * b.z + this->m[3][1];
        result.z = this->m[0][2] * b.x + this->m[1][2] * b.y + this->m[2][2] * b.z + this->m[3][2];

        return result;
    }

    void Identity()
    {
        std::memset(this->m, 0, sizeof(m));
        m[0][0] = m[1][1] = m[2][2] = m[3][3] = 1.0f;
    }

    // Equivalent to glRotate, but left handed. Takes radians
    void Rotate(f32 angle, f32 x, f32 y, f32 z)
    {
        // Rotation matrix takes a counter-clockwise angle
        // angle = -angle;

        f32 angleCos = std::cosf(angle);
        f32 negativeCos = 1 - angleCos;
        f32 angleSin = std::sinf(angle);

        ZunMatrix rotationMatrix;

        rotationMatrix.Identity();

        rotationMatrix.m[0][0] = (x * x) * negativeCos + angleCos;
        rotationMatrix.m[0][1] = (x * y) * negativeCos + z * angleSin;
        rotationMatrix.m[0][2] = (x * z) * negativeCos - y * angleSin;

        rotationMatrix.m[1][0] = (y * x) * negativeCos - z * angleSin;
        rotationMatrix.m[1][1] = (y * y) * negativeCos + angleCos;
        rotationMatrix.m[1][2] = (y * z) * negativeCos + x * angleSin;

        rotationMatrix.m[2][0] = (z * x) * negativeCos + y * angleSin;
        rotationMatrix.m[2][1] = (z * y) * negativeCos - x * angleSin;
        rotationMatrix.m[2][2] = (z * z) * negativeCos + angleCos;

        *this = rotationMatrix * *this;
    }

    // Equivalent to D3DXMatrixRotationQuaternion
    void FromQuaternion(const ZunVec4 &q)
    {
        float x2 = 2.0f * q.x;
        float y2 = 2.0f * q.y;
        float z2 = 2.0f * q.z;

        this->m[0][0] = 1.0f - y2 * q.y - z2 * q.z;
        this->m[0][1] = y2 * q.x + z2 * q.w;
        this->m[0][2] = z2 * q.x - y2 * q.w;
        this->m[0][3] = 0.0f;
        this->m[1][0] = y2 * q.x - z2 * q.w;
        this->m[1][1] = 1.0f - x2 * q.x - z2 * q.z;
        this->m[1][2] = z2 * q.y + x2 * q.w;
        this->m[1][3] = 0.0f;
        this->m[2][0] = z2 * q.x + y2 * q.w;
        this->m[2][1] = z2 * q.y - x2 * q.w;
        this->m[2][2] = 1.0f - x2 * q.x - y2 * q.y;
        this->m[2][3] = 0.0f;
        this->m[3][0] = 0.0f;
        this->m[3][1] = 0.0f;
        this->m[3][2] = 0.0f;
        this->m[3][3] = 1.0f;
    }
};
static_assert(sizeof(ZunMatrix) == 0x40, "ZunMatrix has additional padding between struct members!");

// A viewport using D3D conventions (x, y is the top left corner of the viewport)
struct ZunViewport
{
    i32 X;
    i32 Y;
    i32 Width;
    i32 Height;
    f32 MinZ;
    f32 MaxZ;

    void Set()
    {
        glViewport(this->X, GAME_WINDOW_HEIGHT - (this->Y + this->Height), this->Width, this->Height);
        glDepthRangef(this->MinZ, this->MaxZ);
    }

    void Get()
    {
        GLint viewPortGet[4];
        GLfloat depthRangeGet[2];

        glGetIntegerv(GL_VIEWPORT, viewPortGet);
        glGetFloatv(GL_DEPTH_RANGE, depthRangeGet);

        this->X = viewPortGet[0];
        this->Y = viewPortGet[1];
        this->Width = viewPortGet[2];
        this->Height = viewPortGet[3];
        this->MinZ = depthRangeGet[0];
        this->MaxZ = depthRangeGet[1];

        // Convert from OpenGL to D3D conventions
        this->Y = GAME_WINDOW_HEIGHT - (this->Y + this->Height);
    }
};

#define ZUN_MIN(x, y) ((x) > (y) ? (y) : (x))
#define ZUN_PI ((f32)(3.14159265358979323846))
#define ZUN_2PI ((f32)(ZUN_PI * 2.0f))

#define RADIANS(degrees) ((degrees * ZUN_PI / 180.0f))

#define sincos(in, out_sine, out_cosine)                                                                               \
    {                                                                                                                  \
        out_sine = std::sin(in);                                                                                       \
        out_cosine = std::cos(in);                                                                                     \
    }

inline void fsincos_wrapper(f32 *out_sine, f32 *out_cosine, f32 angle)
{
    *out_sine = std::sin(angle);
    *out_cosine = std::cos(angle);
}

inline void sincosmul(ZunVec3 *out_vel, f32 input, f32 multiplier)
{
    out_vel->x = std::cos(input) * multiplier;
    out_vel->y = std::sin(input) * multiplier;
}

inline f32 invertf(f32 x)
{
    return 1.f / x;
}

inline f32 rintf(f32 float_in)
{
    return std::round(float_in);
}

inline f32 mapRange(f32 in, f32 domainLow, f32 domainHigh, f32 rangeLow, f32 rangeHigh)
{
    // Shift domain to start at 0
    in -= domainLow;
    // Scale domain to have range equal to range of range
    in *= (rangeHigh - rangeLow) / (domainHigh - domainLow);
    // Shift domain to lower value of range
    in += rangeLow;

    return in;
}

// Sets matrix mode to modelview and clobbers current matrix
// Creates a left handed matrix, using the method from Microsoft's docs
inline void createViewMatrix(ZunVec3 &camera, ZunVec3 &target, ZunVec3 &up)
{
    glMatrixMode(GL_MODELVIEW);

    ZunMatrix lookMatrix;

    ZunVec3 xAxis;
    ZunVec3 yAxis;
    ZunVec3 zAxis;

    (target - camera).getNormalized(zAxis);

    up.calcCross(xAxis, zAxis);
    xAxis.getNormalized(xAxis);

    zAxis.calcCross(yAxis, xAxis);

    lookMatrix.m[0][0] = xAxis.x;
    lookMatrix.m[0][1] = yAxis.x;
    lookMatrix.m[0][2] = zAxis.x;
    lookMatrix.m[0][3] = 0.0f;

    lookMatrix.m[1][0] = xAxis.y;
    lookMatrix.m[1][1] = yAxis.y;
    lookMatrix.m[1][2] = zAxis.y;
    lookMatrix.m[1][3] = 0.0f;

    lookMatrix.m[2][0] = xAxis.z;
    lookMatrix.m[2][1] = yAxis.z;
    lookMatrix.m[2][2] = zAxis.z;
    lookMatrix.m[2][3] = 0.0f;

    lookMatrix.m[3][0] = -xAxis.calcDot(camera);
    lookMatrix.m[3][1] = -yAxis.calcDot(camera);
    lookMatrix.m[3][2] = -zAxis.calcDot(camera);
    lookMatrix.m[3][3] = 1.0f;

    glLoadMatrixf((GLfloat *)lookMatrix.m);
}

// Sets matrix mode to projection and clobbers current matrix
inline void perspectiveMatrixFromFOV(f32 verticalFOV, f32 aspectRatio, f32 nearPlane, f32 farPlane)
{
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();

    // D3D has pixels at integer locations, but OpenGL uses half integer pixels. This may need correction
    // https://www.slideshare.net/slideshow/opengl-32-and-more/2172343
    // There are some other clip space differences between D3D and OpenGL, but they shouldn't matter for EoSD

    // This should be uncommented if pixel off-by-one errors show up
    // glTranslatef(0.5f / GAME_WINDOW_WIDTH, 0.5f / GAME_WINDOW_HEIGHT, 0.0f);

    f32 vertical = std::tanf(verticalFOV / 2) * nearPlane;
    f32 horizontal = vertical * aspectRatio;

    glFrustumf(-horizontal, horizontal, -vertical, vertical, nearPlane, farPlane);

    // Change right handed matrix OpenGL generates to a left-handed one to match D3D coordinates
    glScalef(1.0f, 1.0f, -1.0f);
}

// Pushes an identity matrix to the modelview stack and pushes a matrix that maps screen coordinates to
//   NDCs to the projection stack. Used for drawing RHW positions, since D3D interprets them has having
//   been already transformed, but OpenGL has no option to prevent transformation
inline void inverseViewportMatrix()
{
    ZunViewport viewport;

    viewport.Get();

    glMatrixMode(GL_TEXTURE);
    glPushMatrix();
    glLoadIdentity();

    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadIdentity();

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();

    // Mappings:
    //   X: [viewport x .. viewport width] -> [-1 .. 1]
    //   Y: [viewport y .. viewport height] -> [1 .. -1] (Axis inverted since NDCs are cartesian)
    //   Z: [0 .. 1] -> [-1 .. 1]

    // One difference between OpenGL and D3D is that in D3D, pixels are centered on integers, whereas
    //   in OpenGL, they're on half-integer coordinates. Originally, this function finished with a glTranslatef
    //   call to account for this, but OpenGL seems to be very finicky with rasterizing edges on pixel centers,
    //   and most positions in EoSD do use whole integer coordinates for edges (D3D seems to be less
    //   finicky about rasterization). To prevent obvious off-by-one errors with edges in the UI, no accounting
    //   is done for the pixel coordinate discrepancy aside from changing the rounding in DrawOrthographic, if
    //   applied, to use whole integers (OpenGL pixel boundaries), rather than half integers (D3D pixel boundaries).
    //   Graphical output should really be checked thoroughly to make sure nothing (especially in the 3D draw functions)
    //   ends up a half pixel off.

    glTranslatef(-1.0f, 1.0f, -1.0f);
    glScalef(1.0f / (viewport.Width / 2.0f), -1.0f / (viewport.Height / 2.0f), 2.0f);
    glTranslatef(-viewport.X, -viewport.Y, 0.0f);
}

// Reimplementation of D3DXVec3Project. TODO: Replace if possible once port is working
inline void projectVec3(ZunVec3 &out, ZunVec3 &inVec, ZunViewport &viewport, ZunMatrix &projection, ZunMatrix &view,
                        ZunMatrix &world)
{
    // WARNING: Runs into issues if matrices do things with W (Zun's never do)

    ZunVec3 eyeVector = view * world * inVec;
    f32 wVal = eyeVector.z;

    ZunVec3 clipVector = projection * eyeVector;

    clipVector /= wVal;

    // OpenGL clip space and window coordinates differ from D3D's, so we have to invert Y here
    out.x = mapRange(clipVector.x, -1.0f, 1.0f, viewport.X, viewport.X + viewport.Width);
    out.y = mapRange(clipVector.y, -1.0f, 1.0f, viewport.Y + viewport.Height, viewport.Y);
    out.z = mapRange(clipVector.z, -1.0f, 1.0f, viewport.MinZ, viewport.MaxZ);
}
