/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Copying a command subtree, so that one command definition can hang off a
 * second parent.
 */
package cli

import (
	"github.com/spf13/cobra"
)

// cloneCmdTree returns an independent copy of src and its whole subtree.
//
// A *cobra.Command has exactly one parent, so a command that must appear in a
// second tree needs a second command. Normally that means turning the package
// variable into a factory (see NewAuthTree, NewAgentTree). The imr commands
// are the exception worth a copier: they are package-level values shared with
// the tdns-imr daemon's own shell (`tdns-imr --cli` runs the same
// *cobra.Command values in-process), wrapped at init() time (dispatchRemote,
// guardInProcess), and reworking them into factories would put the daemon's
// shell at risk for the sake of a CLI feature. Copying leaves their single
// definition where it is: the instance tree gets whatever the canonical
// command is, including flags added later.
//
// What is copied is every exported field of cobra.Command (TestCloneCopiesEveryCobraField
// fails if a cobra upgrade adds one this does not know), the local and
// persistent flags, and the children. The flags are shared, not duplicated:
// both commands hold the same *pflag.Flag, and so the same variable behind it.
// Only one command runs per invocation, so that is harmless -- the same
// reasoning as for the package-level flag variables the factories bind twice.
//
// The role annotation is NOT copied. It names the tree a command sits in, and
// the copy is about to sit in a different one.
func cloneCmdTree(src *cobra.Command) *cobra.Command {
	return cloneCmd(src, nil)
}

// cloneCmdOnly is cloneCmdTree keeping only those direct children of src for
// which keep(name) is true. Their own subtrees are copied whole.
func cloneCmdOnly(src *cobra.Command, keep func(name string) bool) *cobra.Command {
	return cloneCmd(src, keep)
}

func cloneCmd(src *cobra.Command, keep func(name string) bool) *cobra.Command {
	dst := &cobra.Command{
		Use:                        src.Use,
		Aliases:                    append([]string(nil), src.Aliases...),
		SuggestFor:                 append([]string(nil), src.SuggestFor...),
		Short:                      src.Short,
		GroupID:                    src.GroupID,
		Long:                       src.Long,
		Example:                    src.Example,
		ValidArgs:                  append([]string(nil), src.ValidArgs...),
		ValidArgsFunction:          src.ValidArgsFunction,
		Args:                       src.Args,
		ArgAliases:                 append([]string(nil), src.ArgAliases...),
		BashCompletionFunction:     src.BashCompletionFunction,
		Deprecated:                 src.Deprecated,
		Version:                    src.Version,
		PersistentPreRun:           src.PersistentPreRun,
		PersistentPreRunE:          src.PersistentPreRunE,
		PreRun:                     src.PreRun,
		PreRunE:                    src.PreRunE,
		Run:                        src.Run,
		RunE:                       src.RunE,
		PostRun:                    src.PostRun,
		PostRunE:                   src.PostRunE,
		PersistentPostRun:          src.PersistentPostRun,
		PersistentPostRunE:         src.PersistentPostRunE,
		FParseErrWhitelist:         src.FParseErrWhitelist,
		CompletionOptions:          src.CompletionOptions,
		TraverseChildren:           src.TraverseChildren,
		Hidden:                     src.Hidden,
		SilenceErrors:              src.SilenceErrors,
		SilenceUsage:               src.SilenceUsage,
		DisableFlagParsing:         src.DisableFlagParsing,
		DisableAutoGenTag:          src.DisableAutoGenTag,
		DisableFlagsInUseLine:      src.DisableFlagsInUseLine,
		DisableSuggestions:         src.DisableSuggestions,
		SuggestionsMinimumDistance: src.SuggestionsMinimumDistance,
	}
	if len(src.Annotations) > 0 {
		dst.Annotations = make(map[string]string, len(src.Annotations))
		for k, v := range src.Annotations {
			if k != roleAnnotation {
				dst.Annotations[k] = v
			}
		}
	}

	dst.Flags().AddFlagSet(src.LocalNonPersistentFlags())
	dst.PersistentFlags().AddFlagSet(src.PersistentFlags())

	for _, child := range src.Commands() {
		if keep != nil && !keep(child.Name()) {
			continue
		}
		dst.AddCommand(cloneCmd(child, nil))
	}
	return dst
}
