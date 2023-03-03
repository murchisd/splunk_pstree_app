#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2011-2015 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

#Ps tree logic copied from Giampaolo Rodola's gitub
# Copyright (c) 2009, Giampaolo Rodola'. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#https://github.com/giampaolo
#https://github.com/giampaolo/psutil/blob/master/scripts/pstree.py



from __future__ import absolute_import, division, print_function, unicode_literals
import sys, collections, os
splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'splunk_pstree_app', 'lib'))
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

@Configuration()
class PSTreeCommand(EventingCommand):
        """ Displays a tree structure using a parent and child field from splunk logs. Intended for sysmon EventCode=1 events
        but can be used for anything. App will return a multivalue field for each root process displaying all children
        processes in tree format.

        ##Syntax

        .. code-block::
        pstree parent=<field> child=<field> detail=<field>

        ##Description

        Returns a tree structure of the parent and child fields. Childern will be indented for each  Each  Logs must be received in chronological order
        for accurate results. Details should be associated with the child field.

        ##Example

        Display tree of sysmon process ids.

        .. code-block::
        index=sysmon EventCode=1 | pstree parent=ParentProcessID child=ProcessID

        """

        parent = Option(
        doc='''
        **Syntax:** **parent=***<fieldname>*
        **Description:** Name of the field that holds the parent value''',
        require=True, validate=validators.Fieldname())

        child = Option(
        doc='''
        **Syntax:** **child=***<fieldname>*
        **Description:** Name of the field that holds the child value''',
        require=True, validate=validators.Fieldname())
        
        detail = Option(
        doc='''
        **Syntax:** **detail=***<fieldname>*
        **Description:** Name of the field that holds detail value for child field''',
        require=False, validate=validators.Fieldname())
        
        spaces = Option(
        doc='''
        **Syntax:** **spaces=***int*
        **Description:** Name of the field that holds detail value for child field''',
        require=False, validate=validators.Integer())
        
        method = Option(
        doc='''
        **Syntax:** **method=***str*
        **Description:** Algorithm to use for pstree generation; r for Recursive, i for Iterative (default)''',
        require=False, validate=validators.Set("r","i"))

        def make_tree(self,parent,details, tree, indent, return_array, prefix, spaces):
            #Adjust number of spaces to keep consistently spaced column for details
            space=" "
            if (len(parent)+len(prefix)) < spaces:
                space=space*(spaces-len(prefix)-len(parent))
            # Append line for process in tree
            return_array.append(prefix+parent+space+details)
            # Check to see if current process had any children 
            if parent not in tree:
                    return
            #For every child process recursively build tree
            children = tree[parent].keys()
            for child in children: 
                self.make_tree(child, tree[parent][child],tree, indent + "`` ",return_array, indent + "|--- ",spaces)



        def transform(self, records):
                self.logger.debug('PSTreeCommand: %s', self)  
                #initialize tree structure as dictionary of dictionaries (updated to dict of dict to allow passing of details)
                tree=collections.defaultdict(lambda: collections.defaultdict(str))
                #initialize array to keep track of children processes
                children=[]
                #Set default spaces to 120
                spaces=120
                indent="`` "
                if self.spaces:
                    spaces=self.spaces
                method="i"
                if self.method:
                    method=self.method
                # For every event add parent as key in outer dict and child as key in nested dict
                for record in records:
                    # If detail exists for the event set as value for inner dict other wise set as empty
                    if self.detail:
                        tree[record[self.parent]][record[self.child]]=record[self.detail]
                    else:
                        tree[record[self.parent]][record[self.child]]=""
                    #Add child to array to be able find root of pstree - every process associated with an EventCode 1 will be in this array
                    children.append(record[self.child])
                    
                if method=="r":
                    for parent in tree:
                        #For every parent check if in children array - only Parent Processes with no Process Creation event(Event Code 1) will match this criteria
                        if parent not in children:
                                tmp=[]
                                #Recursively build tree for every root process
                                self.make_tree(parent,'',tree,'',tmp,'',spaces)
                                yield {"tree":tmp}
                else:
                    for parent in tree:
                        #For every parent check if in children array - only Parent Processes with no Process Creation event(Event Code 1) will match this criteria
                        if parent not in children:
                            stack=collections.deque([])
                            branches=[]
                            preorder=[]
                            branches.append(parent)
                            preorder.append(parent)
                            stack.append(parent)
                            depth=-1
                            while len(stack)>0:
                                flag=0
                                if stack[len(stack)-1] not in tree.keys():
                                    stack.pop()
                                    depth=depth-1
                                else:
                                    parent=stack[len(stack)-1]
                                for child in tree[parent].keys():
                                    if child not in preorder:
                                        flag=1
                                        depth=depth+1
                                        stack.append(child)
                                        preorder.append(child)
                                        prefix=(indent*depth)+"|--- "
                                        space=" "
                                        if (len(child)+len(prefix)) < spaces:
                                            space=space*(spaces-len(prefix)-len(child))
                                        branches.append(prefix+child+space+tree[parent][child])
                                        break;
                                if flag==0:
                                    stack.pop()
                                    depth=depth-1

                            yield {"tree":branches}

dispatch(PSTreeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
