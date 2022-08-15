package main

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"test/object"
)

func main() {
	index := strings.IndexByte(FORMAT, '#')
	signedCode := FORMAT[:index]

	if err, errtype := Run(signedCode); err != nil {
		switch errtype {
		case ERROR:
			fmt.Println(err)
		case VM_ERROR:
			PrintMachineError(os.Stdout, err.Error())
		}
	}
}

// ////////////////// ERRORS ////////////////////
type ErrorType string

const (
	ERROR    = "ERROR"
	VM_ERROR = "VM ERROR"
)

func PrintMachineError(out io.Writer, msg string) {
	io.WriteString(out, "\nEven machines aren't perfect 😕. Below error messages may help!\n\n")
	io.WriteString(out, "vm error:")
	io.WriteString(out, "\n\t"+msg+"\t\n")
}

// ErrWrongSignature error is returned if signature doesn't match
var ErrWrongSignature = errors.New("wrong signature, compromised or wrong file")

// ////////////////// GLOBALS ////////////////////
const (
	StackSize  = 2048 * 10
	GlobalSize = 65536 * 10
	MaxFrames  = 2048 * 10
)

// ////////////////// RUNNER ////////////////////
func Run(signedCode string) (error, ErrorType) {
	if err := VerifyCode([]byte(signedCode)); err != nil {
		return err, ERROR
	}

	bytecode, err := decode([]byte(signedCode))
	if err != nil {
		return err, ERROR
	}

	return runvm(bytecode)
}

func decode(data []byte) (*object.ByteCode, error) {
	decodedData, err := decryptCode(data)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(decodedData)

	var bytecode *object.ByteCode
	registerTypes()
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&bytecode); err != nil {
		return nil, err
	}

	return bytecode, nil
}

func decryptCode(signedCode []byte) ([]byte, error) {
	encryptedCode := object.GetEncryptedCode(signedCode)
	decryptedData, err := object.AESDecrypt(encryptedCode)
	if err != nil {
		return nil, err
	}
	decodedData := object.XOR(decryptedData, len(decryptedData))
	return decodedData, nil
}

func runvm(bytecode *object.ByteCode) (error, ErrorType) {
	globals := make([]object.Object, GlobalSize)
	machine := NewWithGlobalStore(bytecode, globals)

	if err := machine.Run(); err != nil {
		return err, VM_ERROR
	}

	last := machine.LastPoppedStackElement()
	io.WriteString(os.Stdout, last.Inspect())
	io.WriteString(os.Stdout, "\n")

	return nil, ""
}

func registerTypes() {
	gob.Register(&object.Integer{})
	gob.Register(&object.Boolean{})
	gob.Register(&object.Null{})
	gob.Register(&object.ReturnValue{})
	gob.Register(&object.Error{})
	gob.Register(&object.Function{})
	gob.Register(&object.String{})
	gob.Register(&object.BuiltIn{})
	gob.Register(&object.Array{})
	gob.Register(&object.Hash{})
	gob.Register(&object.CompiledFunction{})
	gob.Register(&object.Closure{})
	gob.Register(&object.Encrypted{})
}

// ////////////////// SIGNATURES ////////////////////
func VerifyCode(signedCode []byte) error {
	signedCodeString := string(signedCode)
	values := strings.Split(signedCodeString, object.SEPERATOR)

	if values[0] != object.HEADER {
		return ErrWrongSignature
	}

	integrity := md5.New().Sum([]byte(values[1]))
	integString := hex.EncodeToString(integrity)
	if integString != values[2] {
		return ErrWrongSignature
	}

	if values[3] != object.FOOTER {
		return ErrWrongSignature
	}

	return nil
}

// ////////////////// VM  ////////////////////
type Frame struct {
	cl *object.Closure
	ip int
	bp int
}

func NewFrame(cl *object.Closure, basePointer int) *Frame {
	return &Frame{cl: cl, ip: -1, bp: basePointer}
}
func (f *Frame) Instructions() object.Instructions { return f.cl.Fn.Instructions }

type VM struct {
	constants    []object.Object
	stack        []object.Object
	stackPointer int // top of stack is stack[stackPointer-1]
	globals      []object.Object
	frames       []*Frame
	frameIndex   int
	inslen       int
}

func NewWithGlobalStore(bc *object.ByteCode, globals []object.Object) *VM {
	vm := New(bc)
	vm.globals = globals
	return vm
}

func New(bc *object.ByteCode) *VM {
	mainfn := &object.CompiledFunction{Instructions: bc.Instructions}
	frames := make([]*Frame, MaxFrames)

	mainClosure := &object.Closure{Fn: mainfn}
	mainFrame := NewFrame(mainClosure, 0)
	frames[0] = mainFrame

	return &VM{
		constants:    bc.Constants,
		stack:        make([]object.Object, StackSize),
		stackPointer: 0,
		globals:      make([]object.Object, GlobalSize),
		frames:       frames,
		frameIndex:   1,
		inslen:       len(bc.Instructions),
	}
}

func (vm *VM) Run() error {
	var ip int
	var ins object.Instructions
	var op object.Opcode

	for vm.currentFrame().ip < len(vm.currentFrame().Instructions())-1 {
		vm.currentFrame().ip++

		ip = vm.currentFrame().ip
		ins = vm.currentFrame().Instructions()
		ins[ip] = object.XOROne(ins[ip], vm.inslen)
		op = object.Opcode(ins[ip])
		ins[ip] = object.XOROne(ins[ip], vm.inslen)

		switch op {
		case object.OpConstant:
			constIndex := object.ReadUint16(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip += 2

			if err := vm.push(vm.constants[constIndex]); err != nil {
				return err
			}
		case object.OpBang:
			if err := vm.executeBangOperation(); err != nil {
				return err
			}
		case object.OpMinus:
			if err := vm.executeMinusOperation(); err != nil {
				return err
			}
		case object.OpAdd, object.OpSub, object.OpMul, object.OpDiv:
			if err := vm.execBinaryOperation(op); err != nil {
				return err
			}
		case object.OpTrue:
			if err := vm.push(object.True); err != nil {
				return err
			}
		case object.OpFalse:
			if err := vm.push(object.False); err != nil {
				return err
			}
		case object.OpArray:
			numElements := int(object.ReadUint16(ins[ip+1:], vm.inslen))
			vm.currentFrame().ip += 2
			array := vm.buildArray(vm.stackPointer-numElements, vm.stackPointer)
			if err := vm.push(array); err != nil {
				return err
			}
		case object.OpHash:
			numElements := int(object.ReadUint16(ins[ip+1:], vm.inslen))
			vm.currentFrame().ip += 2
			hash, err := vm.buildHash(vm.stackPointer-numElements, vm.stackPointer)
			if err != nil {
				return err
			}
			vm.stackPointer = vm.stackPointer - numElements
			if err := vm.push(hash); err != nil {
				return err
			}
		case object.OpEqual, object.OpUnEqual, object.OpGreater:
			if err := vm.executeComparison(op); err != nil {
				return err
			}
		case object.OpJump:
			pos := int(object.ReadUint16(ins[ip+1:], vm.inslen))
			vm.currentFrame().ip = pos - 1
		case object.OpJumpFalse:
			pos := int(object.ReadUint16(ins[ip+1:], vm.inslen))
			vm.currentFrame().ip += 2
			condition := vm.pop()
			if !isTruthy(condition) {
				vm.currentFrame().ip = pos - 1
			}
		case object.OpSetGlobal:
			globalIndex := object.ReadUint16(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip += 2
			vm.globals[globalIndex] = vm.pop()
		case object.OpGetGlobal:
			globalIndex := object.ReadUint16(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip += 2
			if err := vm.push(vm.globals[globalIndex]); err != nil {
				return err
			}
		case object.OpSetLocal:
			localIndex := object.ReadUint8(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			obj := vm.pop()
			encObj, err := object.EncryptObject(obj, vm.inslen)
			if err != nil {
				vm.stack[frame.bp+int(localIndex)] = obj
			} else {
				vm.stack[frame.bp+int(localIndex)] = encObj
			}
		case object.OpGetLocal:
			localIndex := object.ReadUint8(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			if err := vm.push(vm.stack[frame.bp+int(localIndex)]); err != nil {
				return err
			}
		case object.OpGetBuiltin:
			builtinIndex := object.ReadUint8(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip++
			definition := object.Builtins[builtinIndex]
			if err := vm.push(definition.Builtin); err != nil {
				return err
			}
		case object.OpGetFree:
			freeIndex := object.ReadUint8(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip++
			currentClosure := vm.currentFrame().cl
			if err := vm.push(currentClosure.Free[freeIndex]); err != nil {
				return err
			}
		case object.OpIndex:
			index := vm.pop()
			left := vm.pop()
			if err := vm.execIndexOperation(left, index); err != nil {
				return err
			}
		case object.OpClosure:
			constIndex := object.ReadUint16(ins[ip+1:], vm.inslen)
			numFree := object.ReadUint8(ins[ip+3:], vm.inslen)
			vm.currentFrame().ip += 3
			if err := vm.pushClosure(int(constIndex), int(numFree)); err != nil {
				return err
			}
		case object.OpCurrentClosure:
			currentClosure := vm.currentFrame().cl
			if err := vm.push(currentClosure); err != nil {
				return err
			}
		case object.OpCall:
			numArgs := object.ReadUint8(ins[ip+1:], vm.inslen)
			vm.currentFrame().ip++
			if err := vm.executeCall(int(numArgs)); err != nil {
				return err
			}
		case object.OpReturnValue:
			returnValue := vm.pop()
			frame := vm.popFrame()
			vm.stackPointer = frame.bp - 1
			if err := vm.push(returnValue); err != nil {
				return err
			}
		case object.OpReturn:
			frame := vm.popFrame()
			vm.stackPointer = frame.bp - 1
			if err := vm.push(object.NULL); err != nil {
				return err
			}
		case object.OpNull:
			if err := vm.push(object.NULL); err != nil {
				return err
			}
		case object.OpPop:
			vm.pop()
		}
	}
	return nil
}

func (vm *VM) StackTop() object.Object {
	if vm.stackPointer == 0 {
		return nil
	}

	return vm.stack[vm.stackPointer-1]
}

func (vm *VM) LastPoppedStackElement() object.Object {
	obj := vm.stack[vm.stackPointer]
	if decObj, err := object.DecryptObject(obj, vm.inslen); err == nil {
		obj = decObj
	}
	return obj
}

func (vm *VM) pushClosure(constIndex, numFree int) error {
	constant := vm.constants[constIndex]
	fun, ok := constant.(*object.CompiledFunction)
	if !ok {
		return fmt.Errorf("not a function: %+v", constant)
	}

	free := make([]object.Object, numFree)
	for i := 0; i < numFree; i++ {
		free[i] = vm.stack[vm.stackPointer-numFree+i]
	}
	vm.stackPointer = vm.stackPointer - numFree

	closure := &object.Closure{Fn: fun, Free: free}
	return vm.push(closure)
}

func (vm *VM) push(obj object.Object) error {
	if vm.stackPointer >= StackSize {
		return fmt.Errorf("stack overflow")
	}

	if encObj, err := object.EncryptObject(obj, vm.inslen); err == nil {
		obj = encObj
	}

	vm.stack[vm.stackPointer] = obj
	vm.stackPointer++

	return nil
}

func (vm *VM) pop() object.Object {
	obj := vm.stack[vm.stackPointer-1]
	if newObj, err := object.DecryptObject(obj, vm.inslen); err == nil {
		obj = newObj
	}

	vm.stackPointer--
	return obj
}

func (vm *VM) execBinaryOperation(op object.Opcode) error {
	right := vm.pop()
	left := vm.pop()

	rtype := right.Type()
	ltype := left.Type()

	if rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ {
		return vm.execBinaryIntegerOperation(op, left, right)
	}

	switch {
	case rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ:
		return vm.execBinaryIntegerOperation(op, left, right)
	case rtype == object.STRING_OBJ && ltype == object.STRING_OBJ:
		return vm.execBinaryStringOperation(op, left, right)
	}

	return fmt.Errorf("Unsupported types for binary operation: %s, %s", ltype, rtype)
}

func (vm *VM) execBinaryIntegerOperation(op object.Opcode, left, right object.Object) error {
	rval := right.(*object.Integer).Value
	lval := left.(*object.Integer).Value
	var result int64

	switch op {
	case object.OpAdd:
		result = lval + rval
	case object.OpSub:
		result = lval - rval
	case object.OpMul:
		result = lval * rval
	case object.OpDiv:
		result = lval / rval
	default:
		return fmt.Errorf("Unknown integer operator: %d", op)
	}

	return vm.push(&object.Integer{Value: result})
}

func (vm *VM) execBinaryStringOperation(op object.Opcode, left, right object.Object) error {
	rval := right.(*object.String).Value
	lval := left.(*object.String).Value

	if op != object.OpAdd {
		return fmt.Errorf("Unknown string operator: %d", op)
	}

	return vm.push(&object.String{Value: lval + rval})
}

func (vm *VM) execIndexOperation(left, index object.Object) error {
	switch {
	case left.Type() == object.ARRAY_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execArrayIndex(left, index)
	case left.Type() == object.STRING_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execStringIndex(left, index)
	case left.Type() == object.HASH_OBJ:
		return vm.execHashIndex(left, index)
	default:
		return fmt.Errorf("index operator not supported: %s", left.Type())
	}
}

func (vm *VM) execStringIndex(str, index object.Object) error {
	strVal := str.(*object.String).Value
	i := index.(*object.Integer).Value
	max := int64(len(strVal) - 1)
	if i > max {
		return vm.push(object.NULL)
	} else if i < 0 {
		strObj := &object.String{Value: string(strVal[max+i+1])}
		return vm.push(strObj)
	}
	strObj := &object.String{Value: string(strVal[i])}
	return vm.push(strObj)
}

func (vm *VM) execArrayIndex(array, index object.Object) error {
	arrayObj := array.(*object.Array)
	i := index.(*object.Integer).Value
	max := int64(len(arrayObj.Elements) - 1)
	if i > max {
		return vm.push(object.NULL)
	} else if i < 0 {
		return vm.push(arrayObj.Elements[max+i+1])
	}
	return vm.push(arrayObj.Elements[i])
}

func (vm *VM) execHashIndex(hash, index object.Object) error {
	hashObj := hash.(*object.Hash)

	key, ok := index.(object.Hashable)
	if !ok {
		return fmt.Errorf("unusable as hash key: %s", index.Type())
	}

	pair, ok := hashObj.Pairs[key.HashKey()]
	if !ok {
		return vm.push(object.NULL)
	}

	return vm.push(pair.Value)
}

func (vm *VM) executeBangOperation() error {
	operand := vm.pop()

	switch operand {
	case object.True:
		return vm.push(object.False)
	case object.False:
		return vm.push(object.True)
	case object.NULL:
		return vm.push(object.True)
	default:
		return vm.push(object.False)
	}
}

func (vm *VM) executeMinusOperation() error {
	operand := vm.pop()
	if operand.Type() != object.INTEGER_OBJ {
		return fmt.Errorf("unsupported object type for negation: %s", operand.Type())
	}
	value := operand.(*object.Integer).Value
	return vm.push(&object.Integer{Value: -value})
}

func (vm *VM) executeComparison(op object.Opcode) error {
	right := vm.pop()
	left := vm.pop()

	if left.Type() == object.INTEGER_OBJ || right.Type() == object.INTEGER_OBJ {
		return vm.executeIntegerComparison(op, left, right)
	}

	switch op {
	case object.OpEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() == left.Inspect()))
	case object.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() != left.Inspect()))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

func (vm *VM) executeIntegerComparison(op object.Opcode, left, right object.Object) error {
	leftValue := left.(*object.Integer).Value
	rightValue := right.(*object.Integer).Value
	switch op {
	case object.OpEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue == leftValue))
	case object.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue != leftValue))
	case object.OpGreater:
		return vm.push(nativeBoolToBooleanObject(leftValue > rightValue))
	default:
		return fmt.Errorf("unknown operator: %d", op)
	}
}

func (vm *VM) buildArray(startIndex, endIndex int) object.Object {
	elements := make([]object.Object, endIndex-startIndex)
	for i := startIndex; i < endIndex; i++ {
		elements[i-startIndex] = vm.stack[i]
		element, err := object.DecryptObject(elements[i-startIndex], vm.inslen)
		if err == nil {
			elements[i-startIndex] = element
		}
	}
	return &object.Array{Elements: elements}
}

func (vm *VM) buildHash(startIndex, endIndex int) (object.Object, error) {
	hashedPairs := make(map[object.HashKey]object.HashPair)
	for i := startIndex; i < endIndex; i += 2 {
		key := vm.stack[i]
		value := vm.stack[i+1]

		hkey, err := object.DecryptObject(key, vm.inslen)
		if err == nil {
			key = hkey
		}

		hvalue, err := object.DecryptObject(value, vm.inslen)
		if err == nil {
			value = hvalue
		}

		pair := object.HashPair{Key: key, Value: value}
		hashKey, ok := key.(object.Hashable)
		if !ok {
			return nil, fmt.Errorf("unusable as a hashkey: %s", key.Type())
		}
		hashedPairs[hashKey.HashKey()] = pair
	}
	return &object.Hash{Pairs: hashedPairs}, nil
}

func (vm *VM) currentFrame() *Frame { return vm.frames[vm.frameIndex-1] }
func (vm *VM) pushFrame(f *Frame) {
	vm.frames[vm.frameIndex] = f
	vm.frameIndex++
}
func (vm *VM) popFrame() *Frame {
	vm.frameIndex--
	return vm.frames[vm.frameIndex]
}

func (vm *VM) executeCall(numArgs int) error {
	var callee object.Object
	if vm.stack[vm.stackPointer-1-numArgs].Type() == object.CLOSURE_OBJ || vm.stack[vm.stackPointer-1-numArgs].Type() == object.BUILTIN_OBJ {
		callee = vm.stack[vm.stackPointer-1-numArgs]
	} else {
		callee = vm.stack[0]
	}

	switch calleeType := callee.(type) {
	case *object.Closure:
		return vm.callClosure(calleeType, numArgs)
	case *object.BuiltIn:
		return vm.callBuiltin(calleeType, numArgs)

	default:
		return fmt.Errorf("calling non-function and non-built-in")
	}
}

func (vm *VM) callClosure(cl *object.Closure, numArgs int) error {
	if numArgs != cl.Fn.NumParams {
		return fmt.Errorf("wrong number of arguments. want=%d, got=%d", cl.Fn.NumParams, numArgs)
	}

	frame := NewFrame(cl, vm.stackPointer-numArgs)
	vm.pushFrame(frame)
	vm.stackPointer = frame.bp + cl.Fn.NumLocals
	return nil
}

func (vm *VM) callBuiltin(builtin *object.BuiltIn, numArgs int) error {
	args := vm.stack[vm.stackPointer-numArgs : vm.stackPointer]
	for i := range args {
		dec, err := object.DecryptObject(args[i], vm.inslen)
		if err == nil {
			args[i] = dec
		}
	}
	result := builtin.Fn(args...)

	vm.stackPointer = vm.stackPointer - numArgs - 1

	if result != nil {
		vm.push(result)
	} else {
		vm.push(object.NULL)
	}

	return nil
}

func nativeBoolToBooleanObject(native bool) *object.Boolean {
	if native {
		return object.True
	}
	return object.False
}

func isTruthy(obj object.Object) bool {
	switch obj := obj.(type) {
	case *object.Boolean:
		return obj.Value
	case *object.Null:
		return false
	default:
		return true
	}
}
