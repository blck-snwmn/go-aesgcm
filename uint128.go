package main

import "fmt"

type uint128 struct {
	lhs, rhs uint64
}

func (u uint128) String() string {
	return fmt.Sprintf("%064b, %064b", u.lhs, u.rhs)
}

func (u uint128) rightShift(b uint) uint128 {
	if b > 64 {
		u := u.rightShift(64)
		return u.rightShift(b - 64)
	}
	lhs := u.lhs >> b
	rhs := (u.rhs >> b) | u.lhs<<(64-b)
	return uint128{
		lhs,
		rhs,
	}
}

func (u uint128) xor(other uint128) uint128 {
	return uint128{
		lhs: u.lhs ^ other.lhs,
		rhs: u.rhs ^ other.rhs,
	}
}

func (u uint128) and(other uint128) uint128 {
	return uint128{
		lhs: u.lhs & other.lhs,
		rhs: u.rhs & other.rhs,
	}
}

// func (u uint128) add(other uint128) uint128 {
// 	lhs := u.lhs + other.lhs
// 	rhs := u.rhs + other.rhs
// 	if rhs < u.rhs || rhs < other.rhs {
// 		lhs++
// 	}

// 	return uint128{
// 		lhs,
// 		rhs,
// 	}
// }
