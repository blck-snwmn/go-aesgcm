package main

import (
	"fmt"
	"reflect"
	"testing"
)

func Test_do(t *testing.T) {
	u := uint128{0x8000000000000000, 0x0000000000000000}
	fmt.Println(u)
	u = u.rightShift(127)
	fmt.Println(u)
}

func Test_uint128_rightShiftx(t *testing.T) {
	u := uint128{0x0000000000001123, 0x1234567890123456}
	u = u.rightShift(16)
	if !reflect.DeepEqual(u, uint128{0x0000000000000000, 0x1123123456789012}) {
		t.Fatalf("invalid value, want=%v, got=%v", uint128{0x0000000000000000, 0x1123123456789012}, u)
	}
}

func Test_uint128_rightShift(t *testing.T) {
	type fields struct {
		lhs uint64
		rhs uint64
	}
	type args struct {
		b uint
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   uint128
	}{
		{
			"shift(n<64)",
			fields{0x1200000000001123, 0x1234567890123456},
			args{16},
			uint128{0x0000120000000000, 0x1123123456789012},
		},
		{
			"shift(n=64)",
			fields{0x3400000000001123, 0x1234567890123456},
			args{64},
			uint128{0x0000000000000000, 0x3400000000001123},
		},
		{
			"shift(64<n<128)",
			fields{0x9000000000001123, 0x1234567890123456},
			args{72},
			uint128{0x0000000000000000, 0x0090000000000011},
		},
		{
			"shift(128<n)",
			fields{0x0000000000001123, 0x1234567890123456},
			args{300},
			uint128{0x0000000000000000, 0x000000000000000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := uint128{
				lhs: tt.fields.lhs,
				rhs: tt.fields.rhs,
			}
			if got := u.rightShift(tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uint128.rightShift() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uint128_xor(t *testing.T) {
	type fields struct {
		lhs uint64
		rhs uint64
	}
	type args struct {
		other uint128
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   uint128
	}{
		{
			"0^0",
			fields{0x0000000000000000, 0x0000000000000000},
			args{uint128{0x0000000000000000, 0x000000000000000}},
			uint128{0x0000000000000000, 0x000000000000000},
		},
		{
			// 11110101 01011111
			// 00110011 00110011
			// 11000110 01101100
			"!0^!0",
			fields{0xF500000000000000, 0x000000000000005F},
			args{uint128{0x3300000000000000, 0x000000000000033}},
			uint128{0xC600000000000000, 0x00000000000006C},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := uint128{
				lhs: tt.fields.lhs,
				rhs: tt.fields.rhs,
			}
			if got := u.xor(tt.args.other); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uint128.xor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uint128_and(t *testing.T) {
	type fields struct {
		lhs uint64
		rhs uint64
	}
	type args struct {
		other uint128
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   uint128
	}{
		{
			"0&0",
			fields{0x0000000000000000, 0x0000000000000000},
			args{uint128{0x0000000000000000, 0x000000000000000}},
			uint128{0x0000000000000000, 0x000000000000000},
		},
		{
			// 11110101 01011111
			// 00110011 00110011
			// 00110001 00010011
			"!0&!0",
			fields{0xF500000000000000, 0x000000000000005F},
			args{uint128{0x3300000000000000, 0x000000000000033}},
			uint128{0x3100000000000000, 0x000000000000013},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := uint128{
				lhs: tt.fields.lhs,
				rhs: tt.fields.rhs,
			}
			if got := u.and(tt.args.other); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uint128.and() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func Test_uint128_add(t *testing.T) {
// 	type fields struct {
// 		lhs uint64
// 		rhs uint64
// 	}
// 	type args struct {
// 		other uint128
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		args   args
// 		want   uint128
// 	}{
// 		{
// 			"0+0",
// 			fields{0x0000000000000000, 0x0000000000000000},
// 			args{uint128{0x0000000000000000, 0x000000000000000}},
// 			uint128{0x0000000000000000, 0x000000000000000},
// 		},
// 		{
// 			// 255 17
// 			//  69 34
// 			// 324 51
// 			"add",
// 			fields{0x00000000000000FF, 0x0000000000000011},
// 			args{uint128{0x0000000000000045, 0x000000000000022}},
// 			uint128{0x0000000000000144, 0x000000000000033},
// 		},
// 		{
// 			"overflow(rl)",
// 			fields{0x0000000000000000, 0x0000000000000001},
// 			args{uint128{0x0000000000000000, 0xFFFFFFFFFFFFFFFF}},
// 			uint128{0x0000000000000001, 0x000000000000000},
// 		},
// 		{
// 			"overflow(rr)",
// 			fields{0x0000000000000000, 0xFFFFFFFFFFFFFFFF},
// 			args{uint128{0x0000000000000000, 0x0000000000000001}},
// 			uint128{0x0000000000000001, 0x000000000000000},
// 		},
// 		{
// 			"overflow(l)",
// 			fields{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
// 			args{uint128{0x0000000000000000, 0x0000000000000001}},
// 			uint128{0x0000000000000000, 0x000000000000000},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			u := uint128{
// 				lhs: tt.fields.lhs,
// 				rhs: tt.fields.rhs,
// 			}
// 			if got := u.add(tt.args.other); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("uint128.add() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }
