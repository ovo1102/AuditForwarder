#pragma once
// AuditForwarder - Build configuration macros
// Auto-generated style header centralizing compile-time feature flags.

#ifndef AF_VERSION_MAJOR
#define AF_VERSION_MAJOR 1
#endif

#ifndef AF_VERSION_MINOR
#define AF_VERSION_MINOR 0
#endif

#ifndef AF_VERSION_PATCH
#define AF_VERSION_PATCH 0
#endif

#define AF_VERSION_STRING "1.0.0"

#if defined(_WIN32) || defined(_WIN64)
#  define AF_PLATFORM_WINDOWS 1
#  define AF_PATH_SEPARATOR '\\'
#  define AF_LINE_SEPARATOR "\r\n"
#elif defined(__linux__)
#  define AF_PLATFORM_LINUX 1
#  define AF_PLATFORM_UNIX 1
#  define AF_PATH_SEPARATOR '/'
#  define AF_LINE_SEPARATOR "\n"
#elif defined(__APPLE__)
#  define AF_PLATFORM_DARWIN 1
#  define AF_PLATFORM_UNIX 1
#  define AF_PATH_SEPARATOR '/'
#  define AF_LINE_SEPARATOR "\n"
#else
#  error "Unsupported platform"
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define AF_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define AF_UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define AF_FORCE_INLINE __attribute__((always_inline)) inline
#  define AF_NOINLINE    __attribute__((noinline))
#elif defined(_MSC_VER)
#  define AF_LIKELY(x)   (x)
#  define AF_UNLIKELY(x) (x)
#  define AF_FORCE_INLINE __forceinline
#  define AF_NOINLINE    __declspec(noinline)
#else
#  define AF_LIKELY(x)   (x)
#  define AF_UNLIKELY(x) (x)
#  define AF_FORCE_INLINE inline
#  define AF_NOINLINE
#endif

#if defined(_MSC_VER)
#  define AF_API __declspec(dllexport)
#else
#  define AF_API __attribute__((visibility("default")))
#endif

#ifndef AF_DEFAULT_CONFIG_PATH
#  ifdef AF_PLATFORM_WINDOWS
#    define AF_DEFAULT_CONFIG_PATH "C:\\ProgramData\\AuditForwarder\\agent.yaml"
#  else
#    define AF_DEFAULT_CONFIG_PATH "/etc/auditforwarder/agent.yaml"
#  endif
#endif

#ifndef AF_DEFAULT_DATA_DIR
#  ifdef AF_PLATFORM_WINDOWS
#    define AF_DEFAULT_DATA_DIR "C:\\ProgramData\\AuditForwarder"
#  else
#    define AF_DEFAULT_DATA_DIR "/var/lib/auditforwarder"
#  endif
#endif

#ifndef AF_DEFAULT_LOG_DIR
#  ifdef AF_PLATFORM_WINDOWS
#    define AF_DEFAULT_LOG_DIR "C:\\ProgramData\\AuditForwarder\\log"
#  else
#    define AF_DEFAULT_LOG_DIR "/var/log/auditforwarder"
#  endif
#endif
