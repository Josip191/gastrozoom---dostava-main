<script setup>
import router from "@/router";
</script>

<template>
  <v-btn
    @click="router.go(-1)"
    icon
    variant="tonal"
    color="primary"
    class="custom-radius"
  >
    <v-icon size="2.5rem" class="font-weight-thin">mdi-chevron-left</v-icon>
  </v-btn>
</template>

<style scoped>
  .custom-radius {
    border-radius: 16px;
  }
</style>
