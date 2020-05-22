# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.utils.http import urlencode
from django import forms

import os
import json
import glob
import hashlib
from binascii import hexlify, unhexlify
import traceback

from core.project import Project #TODO rename

#TODO move to forms.py
class projectNameForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x])

class editConfigForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    toolchain = forms.CharField(max_length=100, help_text='Toolchain', validators=[lambda x: not x])
    emulationCFlags = forms.CharField(max_length=1000, help_text='emulationCFlags', validators=[lambda x: not x])
    emulationCodeBase = forms.CharField(help_text="emulationCodeBase", validators=[lambda x: not int(x,16)])
    patchCFlags = forms.CharField(max_length=1000, help_text='patchCFlags', validators=[lambda x: not x])
    patchCodeBase = forms.CharField(help_text="patchCodeBase", validators=[lambda x: not int(x,16)])

class editGroupForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    oldGroupName = forms.CharField(max_length=100, help_text='Old Group Name', validators=[lambda x: not x])
    newGroupName = forms.CharField(max_length=100, help_text='New Group Name', validators=[lambda x: not x])
    active = forms.BooleanField(help_text="Is Segment Active", required=False)

class editSegmentForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    oldSegmentName = forms.CharField(max_length=100, help_text='Old Segment Name', validators=[lambda x: not x])
    oldGroupName = forms.CharField(max_length=100, help_text='Old Group Name', validators=[lambda x: not x])
    newSegmentName = forms.CharField(max_length=100, help_text='New Segment Name', validators=[lambda x: not x])
    newGroupName = forms.CharField(max_length=100, help_text='New Group Name', validators=[lambda x: not x])
    addr = forms.CharField(help_text="Segment Address", validators=[lambda x: not int(x,16)])
    active = forms.BooleanField(help_text="Is Segment Active", required=False)

class editSymbolForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    oldSymbolName = forms.CharField(max_length=100, validators=[lambda x: not x], widget=forms.HiddenInput())
    oldGroupName = forms.CharField(max_length=100, validators=[lambda x: not x], widget=forms.HiddenInput())
    newSymbolName = forms.CharField(max_length=100, help_text='Symbol Name', validators=[lambda x: not x])
    newGroupName = forms.CharField(max_length=100, help_text='Group Name', validators=[lambda x: not x])
    value = forms.CharField(help_text="Value", validators=[lambda x: not int(x,16)])

class loadSegmentForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    segment = forms.FileField(help_text='File', validators=[lambda x: not x])
    addr = forms.CharField(help_text="Segment Address", validators=[lambda x: not int(x,16)])
    groupName = forms.CharField(max_length=100, help_text='Segment Group', validators=[lambda x: not x])

class loadELFForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    elf = forms.FileField(help_text='File', validators=[lambda x: not x])
    loadSymbols = forms.BooleanField(help_text="Load Symbols", required=False, initial=True)
    loadSegments = forms.BooleanField(help_text="Load Segments", required=False, initial=True)
    groupName = forms.CharField(max_length=100, help_text='Segment Group', validators=[lambda x: not x])

class loadIdbForm(forms.Form):
    projectName = forms.CharField(max_length=100, help_text='Project Name', validators=[lambda x: not x], widget=forms.HiddenInput())
    idb = forms.FileField(help_text='File', validators=[lambda x: not x])
    loadFunctions = forms.BooleanField(help_text="Load Functions", required=False, initial=True)
    loadSegments = forms.BooleanField(help_text="Load Segments", required=False, initial=True)


def render_wrapper(request, template, context={}):
    projects = glob.glob("projects/*/project.json")
    projects = map(lambda x: os.path.basename(os.path.dirname(x)), projects)

    context["projects"] = {}
    for projectName in projects:
        emulators = glob.glob(getProjectPath(projectName)+"/gen/*.exe")
        context["projects"][projectName] = map(os.path.basename, emulators)

    if "title" not in context:
        context["title"] = "Frankenstein"

    return render(request, template, context)

"""
Project Management
"""
def getProjectPath(projectName):
    return "projects/"+os.path.basename(projectName)

def getProjectByName(projectName):
    projectPath = "projects/"+os.path.basename(projectName)
    return Project(projectPath)

def index(request):
    return render_wrapper(request, 'index.html')

def project(request):
    projectName = request.GET["projectName"]
    if not os.path.isfile("projects/%s/project.json" % projectName):
        return redirect("/")

    project = getProjectByName(projectName)

    patches = glob.glob(getProjectPath(projectName)+"/gen/*.patch")
    patches = map(os.path.basename, patches)

    context = {
        "title": projectName,
        "projectName": projectName,
        "project": project,
        "patches": patches,
    }
    context['projectNameForm'] = projectNameForm({"projectName": projectName})
    context['editSegmentForm'] = editSegmentForm({"projectName": projectName})
    context['loadSegmentForm'] = loadSegmentForm({"projectName": projectName})
    context['loadELFForm'] = loadELFForm({"projectName": projectName})
    context['loadIdbForm'] = loadIdbForm({"projectName": projectName})

    return render_wrapper(request, 'project.html', context)


def newProject(request):
    if request.method == 'POST':
        form = projectNameForm(request.POST)
        if form.is_valid():
            project = getProjectByName(form.cleaned_data["projectName"])
            project.save()
            return redirect("/")
    else:
        form = projectNameForm()

    context = {}
    context['projectNameForm'] = form
    return render_wrapper(request, 'project/newProject.html', context)

def getProjectCfg(request):
    projectName = request.GET["projectName"]
    if not os.path.isfile("projects/%s/project.json" % projectName):
        redirect("/")

    project = getProjectByName(projectName)
    return HttpResponse(json.dumps(project.cfg))

def projectSanityCheck(request):
    projectName = request.GET["projectName"]
    if not os.path.isfile("projects/%s/project.json" % projectName):
        redirect("/")

    try:
        project = getProjectByName(projectName)
        project.sanity_check()
        return HttpResponse(project.error_msgs)
    except:
        return HttpResponse(traceback.format_exc())
    


"""
Config/Group/Segment/Symbol Management
"""

def editConfig(request):
    if request.method == 'POST':
        form = editConfigForm(request.POST)
        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            project = getProjectByName(projectName)
            succsess = True
            if not project.set_toolchain(form.cleaned_data["toolchain"]):
                succsess = False

            if not project.set_emulation_config(form.cleaned_data["emulationCFlags"], int(form.cleaned_data["emulationCodeBase"], 16)):
                succsess = False
            if not project.set_patch_config(form.cleaned_data["patchCFlags"], int(form.cleaned_data["patchCodeBase"], 16)):
                succsess = False

            if succsess:
                project.save()

            return HttpResponse(project.error_msgs)
    else:
        form = editConfigForm()

    return HttpResponse(str(form.errors))

def editGroup(request):
    if request.method == 'POST':
        form = editGroupForm(request.POST)
        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            oldGroupName = form.cleaned_data["oldGroupName"]
            newGroupName = form.cleaned_data["newGroupName"]
            active = form.cleaned_data["active"]

            project = getProjectByName(projectName)
            if "actionUpdate" in request.POST:
                project.group_update(oldGroupName, newGroupName)
                project.group_set_active(newGroupName, active)
                project.save()
            if "actionDelete" in request.POST:
                project.group_delete(oldGroupName)
                project.save()

            return HttpResponse(project.error_msgs)
    else:
        form = editGroupForm()

    return HttpResponse(str(form.errors))

def editSegment(request):
    if request.method == 'POST':
        form = editSegmentForm(request.POST)
        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            oldSegmentName = form.cleaned_data["oldSegmentName"]
            oldGroupName = form.cleaned_data["oldGroupName"]
            newSegmentName = form.cleaned_data["newSegmentName"]
            newGroupName = form.cleaned_data["newGroupName"]
            active = form.cleaned_data["active"]
            addr = int(form.cleaned_data["addr"], 16)

            project = getProjectByName(projectName)
            if "actionUpdate" in request.POST:
                project.update_segment(oldGroupName, oldSegmentName, newGroupName, newSegmentName, addr)
                project.set_active_segment(newGroupName, newSegmentName, active)
                project.save()
            if "actionDelete" in request.POST:
                project.delete_segment(oldGroupName, oldSegmentName)
                project.save()

            return HttpResponse(project.error_msgs)
    else:
        form = editSegmentForm()

    return HttpResponse(str(form.errors))

def editSymbol(request):
    if request.method == 'POST':
        form = editSymbolForm(request.POST)
        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            oldSymbolName = form.cleaned_data["oldSymbolName"]
            oldGroupName = form.cleaned_data["oldGroupName"]
            newSymbolName = form.cleaned_data["newSymbolName"]
            newGroupName = form.cleaned_data["newGroupName"]
            value = form.cleaned_data["value"]

            project = getProjectByName(projectName)
            if "actionAdd" in request.POST:
                if project.add_symbol(newGroupName, newSymbolName, int(value, 16)):
                    project.save()

            if "actionUpdate" in request.POST:
                if project.update_symbol(oldGroupName, oldSymbolName, newGroupName, newSymbolName, int(value, 16)):
                    project.save()

            if "actionDelete" in request.POST:
                if project.delete_symbol(oldGroupName, oldSymbolName):
                    project.save()

            return HttpResponse(project.error_msgs)
    else:
        form = editSymbolForm()

    return HttpResponse(str(form.errors))


"""
Import Data
"""

def loadELF(request):
    if request.method == 'POST':
        form = loadELFForm(request.POST, request.FILES)

        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            loadSegments = form.cleaned_data["loadSegments"]
            loadSymbols = form.cleaned_data["loadSymbols"]
            groupName = form.cleaned_data["groupName"]
            groupName = "" if groupName == "Create New" else groupName


            try:
                fname = os.path.basename(str(request.FILES['elf']))
                with open('/tmp/%s' % fname, 'wb+') as f:
                    for chunk in request.FILES['elf'].chunks():
                            f.write(chunk)

                project = getProjectByName(form.cleaned_data["projectName"])
                project.load_elf("/tmp/%s" % fname, load_segments=loadSegments, load_symbols=loadSymbols, group=groupName)
                project.save()

                return HttpResponse(project.error_msgs)
            except:
                return HttpResponse(traceback.format_exc())
                
    else:
        form = loadELFForm()

    context = {}
    return HttpResponse(str(form.errors))

def loadIdb(request):
    if request.method == 'POST':
        form = loadIdbForm(request.POST, request.FILES)

        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            loadSegments = form.cleaned_data["loadSegments"]
            loadFunctions = form.cleaned_data["loadFunctions"]
            fname = os.path.basename(str(request.FILES['idb']))
            with open('/tmp/%s' % fname, 'wb+') as f:
                for chunk in request.FILES['idb'].chunks():
                        f.write(chunk)

            try:
                project = getProjectByName(form.cleaned_data["projectName"])
                pe.project.load_idb("/tmp/%s" % fname, load_segments=loadSegments, load_functions=loadFunctions)
                pe.project.save()

                return HttpResponse(project.error_msgs)
            except:
                return HttpResponse(traceback.format_exc())
    else:
        form = loadIdbForm()

    return HttpResponse(str(form.errors))


def loadSegment(request):
    if request.method == 'POST':
        form = loadSegmentForm(request.POST, request.FILES)

        if form.is_valid():
            projectName = form.cleaned_data["projectName"]
            addr = int(form.cleaned_data["addr"], 16)
            groupName = form.cleaned_data["groupName"]
            data = request.FILES['segment'].read()
            fname = os.path.basename(str(request.FILES['segment']))
            segmentName = "%s_0x%x" % (fname, addr)

            try:
                project = getProjectByName(form.cleaned_data["projectName"])
                project.add_segment(groupName, segmentName, addr, data)
                project.save()

                return HttpResponse(project.error_msgs)
            except:
                return HttpResponse(traceback.format_exc())
    else:
        form = loadELFForm()

    return HttpResponse(str(form.errors))


"""
Emulation
"""


from core import uc
import base64

class emulateForm(forms.Form):
    tracepoints = forms.CharField(help_text='RWX Tracepoints', required=False)
    stdin = forms.CharField(help_text='Stdin Hex Dump', required=False)

def emulate(request):
    context = {"success": False}

    projectName = request.GET["projectName"]
    project = getProjectByName(projectName)
    if not project:
        return redirect("/")

    projectPath = getProjectPath(projectName)
    context["title"] = "%s/%s Emulate" % (request.GET["projectName"], request.GET["emulatorName"])

    if request.method == 'POST':
        form = emulateForm(request.POST)
        if form.is_valid():
            tracepoints = form.cleaned_data["tracepoints"]
            if len(tracepoints) > 2:
                for w in " \r\n\t":
                    tracepoints = tracepoints.replace(w, ",")

                tracepoints = filter(lambda x: len(x) > 0, tracepoints.split(","))
                tracepoints = list(map(lambda x:int(x,16), tracepoints))
            else:
                tracepoints = []

            try:
                stdin = form.cleaned_data["stdin"]
                stdin = stdin.replace(" ", "").replace("\n", "").replace("\r", "")
                print(stdin)
                stdin = unhexlify(stdin)
            except:
                import traceback; traceback.print_exc()
                stdin = ""

            binaryPath = os.path.join(projectPath, "gen", request.GET["emulatorName"])
            emulator = uc.emu(binaryPath, stdin, tracepoints, emulator_base=project.cfg["config"]["EMULATION_CODE_BASE"])
            emulator.run()

            #prepare results for html
            results = emulator.results
            from ansi2html import Ansi2HTMLConverter
            conv = Ansi2HTMLConverter()
            for r in results:
                del r["stdout"]
                r["pc_symbolized"] = project.symbolize(r["regs"]["pc"])
                r["stderr"] = base64.b64encode(r["stderr"].encode("utf-8")).decode("utf-8")
                r["memdif_rendered"] = base64.b64encode(r["memdif_rendered"].encode("utf-8")).decode("utf-8")
                r["memdif_html"] = base64.b64encode(conv.convert(r["memdif_rendered"]).encode("utf-8")).decode("utf-8")

            emulator.coverage_activity_json = json.dumps(emulator.coverage_activity)
            emulator.read_activity_json = json.dumps(emulator.read_activity)
            emulator.write_activity_json = json.dumps(emulator.write_activity)


            #context["segments"] = sorted(project.cfg["segments"].items(), key=lambda x: x[1]["addr"])
            context["symbols_json"] = json.dumps(project.get_symbols())
            context["emulator"] = emulator
            context["tracefile_b64"] = base64.b64encode(emulator.get_tracefile()).decode()
            context["project"] = project
            context["success"] = True


    else:
        form = emulateForm()


    context["emulateForm"] = form
    context["projectName"] = projectName
    context["emulatorName"] = request.GET["emulatorName"]

    return render_wrapper(request, 'emulate.html', context)
