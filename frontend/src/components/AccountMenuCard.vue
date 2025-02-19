<script setup>

defineProps({
  link: {
    type: String,
    default: '',
  },
  prependIcon: {
    type: String,
    default: '',
  },
  title: {
    type: String,
    default: 'Naziv jela',
  },
  appendText: {
    type: String,
    default: '',
  },
});
</script>

<template>
  <RouterLink :to="link" class="text-decoration-none w-100">
    <v-card class="d-flex align-center mb-2 pa-2 custom-shadow" rounded="xl" variant="text">
      <template v-slot:prepend>
        <v-icon class="text-primary">{{ prependIcon }}</v-icon>
      </template>
      <v-card-title class="text-subtitle-1 text-sm-h6 text-start text-black">{{ title }}</v-card-title>

      <v-card-text v-if="appendText !== ''" class="text-h4 font-weight-medium text-end mr-sm-4 mt-3 text-subtitle-1">{{ appendText }}</v-card-text>
    </v-card>
  </RouterLink>
</template>

<style scoped>
.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}

</style>
