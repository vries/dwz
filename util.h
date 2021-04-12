/* Copyright (C) 2001-2021 Red Hat, Inc.
   Copyright (C) 2003 Free Software Foundation, Inc.
   Copyright (C) 2019-2021 SUSE LLC.
   Written by Jakub Jelinek <jakub@redhat.com>, 2012.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* Utility macros.  */

#define IMPLIES(A, B) (!((A) && !(B)))

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))

#define XSTR(s) STR(s)
#define STR(s) #s

#ifndef USE_GNUC
#ifdef __GNUC__
#define USE_GNUC 1
#else
#define USE_GNUC 0
#endif
#endif

#if USE_GNUC && __GNUC__ >= 3
# define likely(x) __builtin_expect (!!(x), 1)
# define unlikely(x) __builtin_expect (!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

#if USE_GNUC
# define FORCE_INLINE __attribute__((always_inline))
# define UNUSED __attribute__((unused))
# define USED __attribute__((used))
#else
# define FORCE_INLINE
# define UNUSED
# define USED
#endif

#if USE_GNUC
# define ALIGN_STRUCT(name)
# define ALIGNOF_STRUCT(name) __alignof__ (struct name)
#else
# define ALIGN_STRUCT(name) struct align_##name { char c; struct name s; };
# define ALIGNOF_STRUCT(name) offsetof (struct align_##name, s)
#endif
