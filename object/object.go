package object

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	mathRand "math/rand"
	"reflect"
	"strconv"
	"strings"
)

type Instructions []byte

type ByteCode struct {
	Instructions Instructions
	Constants    []Object
}

type Opcode byte

const (
	OpConstant Opcode = iota
	OpPop
	OpAdd
	OpSub
	OpMul
	OpDiv
	OpTrue
	OpFalse
	OpEqual
	OpUnEqual
	OpGreater
	OpMinus
	OpBang
	OpJumpFalse
	OpJump
	OpNull
	OpGetGlobal
	OpSetGlobal
	OpGetLocal
	OpSetLocal
	OpArray
	OpHash
	OpIndex
	OpCall
	OpReturnValue
	OpReturn
	OpGetBuiltin
	OpClosure
	OpGetFree
	OpCurrentClosure
)

func ReadUint16(ins Instructions, length int) uint16 {
	ins = XOR(ins, length)
	index := binary.BigEndian.Uint16(ins)
	ins = XOR(ins, length)
	return index
}
func ReadUint8(ins Instructions, length int) uint8 {
	ins[0] = XOROne(ins[0], length)
	index := uint8(ins[0])
	ins[0] = XOROne(ins[0], length)
	return index
}

type TokenType string

type Token struct {
	Type    TokenType
	Literal string
}

type Identifier struct {
	Token Token // IDENT token
	Value string
}

func (i *Identifier) expressionNode()      {}
func (i *Identifier) TokenLiteral() string { return i.Token.Literal }
func (i *Identifier) String() string       { return i.Value }

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
	statementNode()
}

type BlockStatement struct {
	Token      Token
	Statements []Statement
}

func (bs *BlockStatement) statementNode()       {}
func (bs *BlockStatement) TokenLiteral() string { return bs.Token.Literal }
func (bs *BlockStatement) String() string {
	var out bytes.Buffer

	for _, s := range bs.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}

const (
	HEADER    = "MUT"
	FOOTER    = "ANT"
	ENCSIG    = "MUTANT"
	SEPERATOR = "|"
)

func GetEncryptedCode(signedCode []byte) string {
	signedCodeString := string(signedCode)
	return strings.Split(signedCodeString, SEPERATOR)[1]
}

func AESDecrypt(encodedCipherData string) ([]byte, error) {
	cipData, err := base64.StdEncoding.DecodeString(encodedCipherData)
	if err != nil {
		return nil, err
	}

	values := strings.Split(string(cipData), SEPERATOR)
	cipherString := values[0]
	keyString := values[1]

	cypher, err := base64.StdEncoding.DecodeString(cipherString)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cypher) < nonceSize {
		return nil, errors.New("wrong nonce")
	}

	nonce, cipherText := cypher[:nonceSize], cypher[nonceSize:]
	data, err := gcm.Open(nil, nonce, cipherText, []byte(ENCSIG))

	return data, nil
}

// XOR function performs xor on a byte array
func XOR(data []byte, length int) []byte {
	key := randByte(int64(length))
	for i := range data {
		data[i] ^= key
	}
	return data
}

// XOROne funciton performs xor on a single byte(instruction)
func XOROne(instruction byte, length int) byte {
	key := randByte(int64(length))
	return instruction ^ key
}

func randByte(seed int64) byte {
	src := mathRand.NewSource(seed)
	newrand := mathRand.New(src)
	number := newrand.Int()
	return byte(number)
}

func EncryptByteCode(byteCode *ByteCode) *ByteCode {
	byteCode.Instructions = XOR(byteCode.Instructions, len(byteCode.Instructions))
	insLen := len(byteCode.Instructions)

	for i := range byteCode.Constants {
		if byteCode.Constants[i].Type() == COMPILED_FN_OBJ {
			ins := byteCode.Constants[i].(*CompiledFunction).Instructions
			ins = XOR(ins, insLen)
			byteCode.Constants[i].(*CompiledFunction).Instructions = ins
		} else {
			if encConst, err := EncryptObject(byteCode.Constants[i], insLen); err == nil {
				byteCode.Constants[i] = encConst
			}
		}
	}

	return byteCode
}

func EncryptObject(obj Object, length int) (Object, error) {
	var encObj Object
	var err error

	switch obj.Type() {
	case INTEGER_OBJ:
		val := obj.(*Integer).Value
		bite := make([]byte, 8)
		binary.LittleEndian.PutUint64(bite, uint64(val))
		bite = XOR(bite, length)

		encObj = &Encrypted{
			EncType: INTEGER_OBJ,
			Value:   bite,
		}

	case STRING_OBJ:
		val := obj.(*String).Value
		bite := XOR([]byte(val), length)

		encObj = &Encrypted{
			EncType: STRING_OBJ,
			Value:   bite,
		}

	case BOOLEAN_OBJ:
		val := obj.(*Boolean).Value
		str := strconv.FormatBool(val)
		bite := XOR([]byte(str), length)

		encObj = &Encrypted{
			EncType: BOOLEAN_OBJ,
			Value:   bite,
		}

	default:
		err = errors.New("wrong obj type")
	}

	return encObj, err
}

func DecryptObject(obj Object, length int) (Object, error) {
	decObj := obj
	var err error

	if decObj.Type() == ENCRYPTED_OBJ {
		biteVal := decObj.(*Encrypted).Value
		bite := make([]byte, len(biteVal))
		copy(bite, biteVal)
		bite = XOR(bite, length)

		switch decObj.(*Encrypted).EncType {
		case INTEGER_OBJ:
			val := binary.LittleEndian.Uint64(bite)
			decObj = &Integer{Value: int64(val)}

		case STRING_OBJ:
			decObj = &String{Value: string(bite)}

		case BOOLEAN_OBJ:
			str := strings.ToLower(string(bite))
			if str == "true" {
				decObj = True
			} else {
				decObj = False
			}
		}

		return decObj, nil
	}

	err = errors.New("wrong obj type")
	return obj, err
}

type ObjectType string

const (
	INTEGER_OBJ      = "INTEGER"
	BOOLEAN_OBJ      = "BOOLEAN"
	NULL_OBJ         = "NULL"
	RETURN_VALUE_OBJ = "RETURN_VALUE"
	ERROR_OBJ        = "ERROR_OBJ"
	FUNCTION_OBJ     = "FUNCTION"
	STRING_OBJ       = "STRING"
	BUILTIN_OBJ      = "BUILTIN"
	ARRAY_OBJ        = "ARRAY"
	HASH_OBJ         = "HASH"
	QUOTE_OBJ        = "QUOTE"
	MACRO_OBJ        = "MACRO"
	COMPILED_FN_OBJ  = "COMPILED_FN_OBJ"
	CLOSURE_OBJ      = "CLOSURE"
	ENCRYPTED_OBJ    = "ENCRYPTED"
)

type Object interface {
	Type() ObjectType
	Inspect() string
}

// True is the object version of golang native true
var True = &Boolean{Value: true}

// False is the object version of golang native false
var False = &Boolean{Value: false}

// Null is the object version of golang native null
var NULL = &Null{}

////////// ARRAY //////////
type Array struct{ Elements []Object }

func (ao *Array) Type() ObjectType { return ARRAY_OBJ }
func (ao *Array) Inspect() string {
	var out bytes.Buffer
	elements := []string{}

	for _, e := range ao.Elements {
		elements = append(elements, e.Inspect())
	}

	out.WriteString("[")
	out.WriteString(strings.Join(elements, ", "))
	out.WriteString("]")

	return out.String()
}

////////// BOOLEAN //////////
type Boolean struct {
	Value bool
}

func (b *Boolean) Type() ObjectType { return BOOLEAN_OBJ }
func (b *Boolean) Inspect() string  { return fmt.Sprintf("%t", b.Value) }

////////// BUILTIN //////////
type BuiltinFunction func(args ...Object) Object
type BuiltIn struct{ Fn BuiltinFunction }

func (b *BuiltIn) Type() ObjectType { return BUILTIN_OBJ }
func (b *BuiltIn) Inspect() string  { return "builtin funciton" }

var Builtins = []struct {
	Name    string
	Builtin *BuiltIn
}{
	{
		Name: "len",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 1 {
					return newError("wrong number of arguments. got=%d, want=1", len(args))
				}
				switch arg := args[0].(type) {
				case *Array:
					return &Integer{Value: int64(len(arg.Elements))}
				case *String:
					return &Integer{Value: int64(len(arg.Value))}
				default:
					return newError("argument to `len` not supported, got %s", args[0].Type())
				}
			},
		},
	},
	{
		Name: "puts",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				for _, arg := range args {
					fmt.Print(arg.Inspect())
				}
				return nil
			},
		},
	},
	{
		Name: "putln",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				for _, arg := range args {
					fmt.Println(arg.Inspect())
				}
				return nil
			},
		},
	},
	{
		Name: "gets",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 1 {
					return newError("wrong number of arguments. got=%d, want=1", len(args))
				}

				if args[0] == nil || (reflect.ValueOf(args[0]).Kind() == reflect.Ptr && reflect.ValueOf(args[0]).IsNil()) {
					return newError("argument to function is nil :/")
				}

				if args[0].Type() == STRING_OBJ {
					switch args[0].Inspect() {
					case "boolean":
						fallthrough
					case "bool":
						fallthrough
					case "BOOL":
						fallthrough
					case "BOOLEAN":
						var in bool
						if _, err := fmt.Scanln(&in); err != nil {
							return newError("input does not match declared data type")
						}
						return &Boolean{Value: in}
					case "integer":
						fallthrough
					case "int":
						fallthrough
					case "INT":
						fallthrough
					case "INTEGER":
						var in int64
						if _, err := fmt.Scanln(&in); err != nil {
							return newError("input does not match declared data type")
						}
						return &Integer{Value: in}
					case "string":
						fallthrough
					case "str":
						fallthrough
					case "STR":
						fallthrough
					case "STRING":
						var in string
						if _, err := fmt.Scanln(&in); err != nil {
							return newError("input does not match declared data type")
						}
						return &String{Value: in}
					default:
						return nil
					}
				}

				return newError("argument to `gets` must be a string declaring data type for user input. Ex: BOOLEAN or INTEGER or STRING, got %s", args[0].Type())
			},
		},
	},
	{
		Name: "first",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 1 {
					return newError("wrong number of arguments. got=%d, want=1", len(args))
				}

				if args[0].Type() != ARRAY_OBJ {
					return newError("argument to `first` must be ARRAY, got %s", args[0].Type())
				}

				arr := args[0].(*Array)
				if len(arr.Elements) > 0 {
					return arr.Elements[0]
				}

				return nil
			},
		},
	},
	{
		Name: "last",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 1 {
					return newError("wrong number of arguments. got=%d, want=1", len(args))
				}

				if args[0].Type() != ARRAY_OBJ {
					return newError("argument to `last` must be ARRAY, got %s", args[0].Type())
				}

				arr := args[0].(*Array)
				length := len(arr.Elements)
				if length > 0 {
					return arr.Elements[length-1]
				}

				return nil
			},
		},
	},
	{
		Name: "rest",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 1 {
					return newError("wrong number of arguments. got=%d, want=1", len(args))
				}
				if args[0].Type() != ARRAY_OBJ {
					return newError("argument to `rest` must be ARRAY, got=%s", args[0].Type())
				}

				arr := args[0].(*Array)
				length := len(arr.Elements)
				if length > 1 {
					newElements := make([]Object, length-1, length-1)
					copy(newElements, arr.Elements[1:length])
					return &Array{Elements: newElements}
				}
				return nil
			},
		},
	},
	{
		Name: "push",
		Builtin: &BuiltIn{
			Fn: func(args ...Object) Object {
				if len(args) != 2 {
					return newError("wrong number of arguments. got=%d, want=2", len(args))
				}

				if args[0].Type() != ARRAY_OBJ {
					return newError("argument to `push` must be ARRAY, got=%s", args[0].Type())
				}

				arr := args[0].(*Array)
				length := len(arr.Elements)

				newElements := make([]Object, length+1, length+1)
				copy(newElements, arr.Elements)
				newElements[length] = args[1]

				return &Array{Elements: newElements}
			},
		},
	},
}

func GetBuiltinByName(name string) *BuiltIn {
	for _, fun := range Builtins {
		if name == fun.Name {
			return fun.Builtin
		}
	}
	return nil
}

func newError(format string, a ...interface{}) *Error {
	return &Error{Message: fmt.Sprintf(format, a...)}
}

////////// CLOSURE //////////
type Closure struct {
	Fn   *CompiledFunction
	Free []Object
}

func (c *Closure) Type() ObjectType { return CLOSURE_OBJ }
func (c *Closure) Inspect() string  { return fmt.Sprintf("Closure[%p]", c) }

////////// COMPILED FUN OBJ //////////
type CompiledFunction struct {
	Instructions Instructions
	NumLocals    int
	NumParams    int
}

func (cf *CompiledFunction) Type() ObjectType { return COMPILED_FN_OBJ }
func (cf *CompiledFunction) Inspect() string  { return fmt.Sprintf("Compiled Function[%p]", cf) }

////////// ENCRYPTED //////////
type Encrypted struct {
	Value   []byte
	EncType ObjectType
}

func (e *Encrypted) Type() ObjectType { return ENCRYPTED_OBJ }
func (e *Encrypted) Inspect() string  { return fmt.Sprintf("%v", e.Value) }

////////// ENV //////////
type Environment struct {
	store map[string]Object
	outer *Environment
}

func NewEnvironment() *Environment {
	s := make(map[string]Object)
	return &Environment{store: s, outer: nil}
}

func NewEnclosedEnvironement(outer *Environment) *Environment {
	env := NewEnvironment()
	env.outer = outer
	return env
}

func (e *Environment) Get(name string) (Object, bool) {
	obj, ok := e.store[name]
	if (!ok) && (e.outer != nil) {
		obj, ok = e.outer.Get(name)
	}
	return obj, ok
}

func (e *Environment) Set(name string, val Object) Object {
	e.store[name] = val
	return val
}

////////// ERROR //////////
type Error struct{ Message string }

func (e *Error) Type() ObjectType { return ERROR_OBJ }
func (e *Error) Inspect() string  { return "ERROR:" + e.Message }

////////// FN //////////
type Function struct {
	Parameters []*Identifier
	Body       *BlockStatement
	Env        *Environment
}

func (f *Function) Type() ObjectType { return FUNCTION_OBJ }
func (f *Function) Inspect() string {
	var out bytes.Buffer
	params := []string{}

	for _, p := range f.Parameters {
		params = append(params, p.String())
	}

	out.WriteString("fn")
	out.WriteString("(")
	out.WriteString(strings.Join(params, ", "))
	out.WriteString(") {\n")
	out.WriteString(f.Body.String())
	out.WriteString("\n}")

	return out.String()
}

////////// HASH //////////
type HashKey struct {
	Type  ObjectType
	Value uint64
}

type HashPair struct {
	Key   Object
	Value Object
}

type Hash struct{ Pairs map[HashKey]HashPair }

type Hashable interface{ HashKey() HashKey }

func (b *Boolean) HashKey() HashKey {
	var value uint64
	if b.Value {
		value = 1
	} else {
		value = 0
	}
	return HashKey{Type: b.Type(), Value: value}
}

func (i *Integer) HashKey() HashKey {
	return HashKey{Type: i.Type(), Value: uint64(i.Value)}
}

func (s *String) HashKey() HashKey {
	h := fnv.New64a()
	h.Write([]byte(s.Value))
	return HashKey{Type: s.Type(), Value: h.Sum64()}
}

func (h *Hash) Type() ObjectType { return HASH_OBJ }
func (h *Hash) Inspect() string {
	var out bytes.Buffer
	pairs := []string{}

	for _, pair := range h.Pairs {
		pairs = append(pairs, fmt.Sprintf("%s: %s", pair.Key.Inspect(), pair.Value.Inspect()))
	}

	out.WriteString("{")
	out.WriteString(strings.Join(pairs, ", "))
	out.WriteString("}")

	return out.String()
}

////////// INT //////////
type Integer struct {
	Value int64
}

func (i *Integer) Type() ObjectType { return INTEGER_OBJ }
func (i *Integer) Inspect() string  { return fmt.Sprintf("%d", i.Value) }

////////// NULL //////////
type Null struct{}

func (n *Null) Type() ObjectType { return NULL_OBJ }
func (n *Null) Inspect() string  { return "" }

////////// RETURN //////////
type ReturnValue struct{ Value Object }

func (rv *ReturnValue) Type() ObjectType { return RETURN_VALUE_OBJ }
func (rv *ReturnValue) Inspect() string  { return rv.Value.Inspect() }

////////// STRING //////////
type String struct{ Value string }

func (s *String) Type() ObjectType { return STRING_OBJ }
func (s *String) Inspect() string  { return s.Value }
