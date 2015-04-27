

TEXT ·xorinto(SB),0,$0
  MOVQ state+0(FP),DI
  MOVQ in+8(FP),SI
  MOVQ count+16(FP),CX
  MOVQ offset+24(FP),DX

#define IN SI
#define STATE DI
#define COUNT CX
#define OFFSET DX
  ADDQ STATE,OFFSET
  ADDQ IN,COUNT
  ADDQ STATE,COUNT
  NEGQ COUNT

  CMPQ COUNT, -16
  JGE 
