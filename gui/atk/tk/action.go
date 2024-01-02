// Copyright 2018 visualfc. All rights reserved.

package tk

import (
	"fmt"
)

type Action struct {
	actid   string
	label   string
	checkid string
	groupid string
	radioid string
	command *Command
	data    interface{}
}

func (a *Action) String() string {
	if a.actid == "" {
		return "Separator"
	} else if a.groupid != "" {
		return fmt.Sprintf("RadioAction{%v}", a.label)
	} else if a.checkid != "" {
		return fmt.Sprintf("CheckAction{%v}", a.label)
	} else {
		return fmt.Sprintf("Action{%v}", a.label)
	}
}

func (a *Action) IsSeparator() bool {
	return a.actid == ""
}

func (a *Action) IsRadioAction() bool {
	return a.groupid != ""
}

func (a *Action) IsCheckAction() bool {
	return a.checkid != ""
}

func (a *Action) SetChecked(b bool) {
	if a.groupid != "" {
		eval(fmt.Sprintf("set %v {%v}", a.groupid, a.radioid))
	} else if a.checkid != "" {
		eval(fmt.Sprintf("set %v {%v}", a.checkid, boolToInt(b)))
	}
}

func (a *Action) IsChecked() bool {
	if a.groupid != "" {
		r, _ := evalAsString(fmt.Sprintf("set %v", a.groupid))
		return r == a.radioid
	} else if a.checkid != "" {
		b, _ := evalAsBool(fmt.Sprintf("set %v", a.checkid))
		return b
	}
	return false
}

func (a *Action) Label() string {
	return a.label
}

func (a *Action) SetData(data interface{}) {
	a.data = data
}

func (a *Action) Data() interface{} {
	return a.data
}

func (a *Action) Invoke() {
	a.command.Invoke()
}

func (a *Action) OnCommand(fn func()) error {
	if fn == nil {
		return ErrInvalid
	}
	a.command.Bind(fn)
	return nil
}

func NewAction(label string) *Action {
	act := &Action{}
	act.label = label
	act.actid = makeActionId()
	act.command = &Command{}
	mainInterp.CreateAction(act.actid, func([]string) {
		act.command.Invoke()
	})
	return act
}

func NewActionEx(label string, cmd func()) *Action {
	act := NewAction(label)
	act.OnCommand(cmd)
	return act
}

func NewCheckAction(label string) *Action {
	act := NewAction(label)
	id := makeNamedId("atk_checkaction")
	evalSetValue(id, "0")
	act.checkid = id
	return act
}

func NewCheckActionEx(label string, cmd func()) *Action {
	act := NewCheckAction(label)
	act.OnCommand(cmd)
	return act
}

func NewRadioAction(group *ActionGroup, label string) *Action {
	return group.AddNewRadioAction(label)
}

func NewSeparatorAction() *Action {
	action := &Action{}
	return action
}

type ActionGroup struct {
	groupid        string
	actions        []*Action
	fnRadioCommand func()
}

func NewActionGroup() *ActionGroup {
	id := makeNamedId("atk_actiongroup")
	evalSetValue(id, "")
	return &ActionGroup{id, nil, nil}
}

func (a *ActionGroup) findAction(act *Action) bool {
	for _, v := range a.actions {
		if v == act {
			return true
		}
	}
	return false
}

func (a *ActionGroup) radioCommand() {
	if a.fnRadioCommand != nil {
		a.fnRadioCommand()
	}
}

func (a *ActionGroup) AddRadioAction(act *Action) error {
	if a.findAction(act) {
		return ErrExist
	}
	act.groupid = a.groupid
	act.radioid = makeNamedId("atk_radioaction")
	act.OnCommand(a.radioCommand)
	a.actions = append(a.actions, act)
	return nil
}

func (a *ActionGroup) AddNewRadioAction(label string) *Action {
	act := NewAction(label)
	a.AddRadioAction(act)
	return act
}

func (a *ActionGroup) OnCommand(fn func()) {
	a.fnRadioCommand = fn
}

func (a *ActionGroup) checkedValue() string {
	r, _ := evalAsStringEx(fmt.Sprintf("set %v", a.groupid), false)
	return r
}

func (a *ActionGroup) SetCheckedIndex(index int) error {
	if index < 0 || index > len(a.actions) {
		return ErrInvalid
	}
	a.actions[index].SetChecked(true)
	return nil
}

func (a *ActionGroup) SetCheckedAction(act *Action) error {
	if act == nil {
		return ErrInvalid
	}
	for _, v := range a.actions {
		if v == act {
			act.SetChecked(true)
			return nil
		}
	}
	return ErrNotExist
}

func (a *ActionGroup) CheckedActionIndex() int {
	s := a.checkedValue()
	if s == "" {
		return -1
	}
	for n, act := range a.actions {
		if act.radioid == s {
			return n
		}
	}
	return -1
}

func (a *ActionGroup) CheckedAction() *Action {
	s := a.checkedValue()
	if s == "" {
		return nil
	}
	for _, act := range a.actions {
		if act.radioid == s {
			return act
		}
	}
	return nil
}

func (a *ActionGroup) Actions() []*Action {
	return a.actions
}
