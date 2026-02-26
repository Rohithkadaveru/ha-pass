// Shared domain configuration — single source of truth for guest + admin UIs.
// To add a new HA entity domain, edit only this file.
const DOMAIN_ORDER = ['light','switch','input_boolean','climate','lock','media_player','cover','fan'];
const DOMAIN_LABELS = {
  light: 'Lights', switch: 'Switches', input_boolean: 'Switches', climate: 'Climate',
  lock: 'Locks', media_player: 'Media', cover: 'Covers', fan: 'Fans',
};
const DOMAIN_ICONS = {
  light: 'lightbulb', switch: 'toggle_on', input_boolean: 'toggle_on', climate: 'thermostat',
  lock: 'lock', media_player: 'speaker', cover: 'blinds', fan: 'mode_fan',
};
const DOMAIN_COLORS = {
  light: { bg: 'bg-amber-500/10', text: 'text-amber-500', icon: 'bg-amber-500' },
  switch: { bg: 'bg-teal-600/10', text: 'text-teal-600', icon: 'bg-teal-600' },
  input_boolean: { bg: 'bg-teal-600/10', text: 'text-teal-600', icon: 'bg-teal-600' },
  climate: { bg: 'bg-blue-500/10', text: 'text-blue-500', icon: 'bg-blue-500' },
  lock: { bg: 'bg-red-500/10', text: 'text-red-500', icon: 'bg-red-500' },
  media_player: { bg: 'bg-purple-500/10', text: 'text-purple-500', icon: 'bg-purple-500' },
  cover: { bg: 'bg-sky-500/10', text: 'text-sky-500', icon: 'bg-sky-500' },
  fan: { bg: 'bg-emerald-500/10', text: 'text-emerald-500', icon: 'bg-emerald-500' },
};
